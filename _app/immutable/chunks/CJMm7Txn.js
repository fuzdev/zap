import{$ as e,G as t,J as ee,K as te,X as n,Z as ne,dt as r,ft as i,j as a,k as re,l as o,m as s,ot as c,st as l}from"./CkSeWg2M.js";import{t as u}from"./Cyt8LZpN.js";import{n as ie}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as d}from"./k6TRNp0w.js";import{t as f}from"./DH_LefOd.js";import{t as p}from"./CtsBFaJL.js";var ae=a(`<p>A Zap config (<code>zap.ts</code>) declares <strong>resources</strong>: typed descriptions of desired
machine state. Zap detects the live state, compares it to the declared
resources, and applies the smallest set of changes that converges them. Each
resource has a stable <code>id</code>, an optional <code>name</code>, an optional <code>depends_on</code> list,
and a kind, set by the builder method you call (it becomes the <code>type</code> in the JSON
the config evaluates to).</p><!><h2>Resource types</h2><table><thead><tr><th>Builder method</th><th>Type</th><th>What it declares</th></tr></thead><tbody><tr><td><code>zap.pkg</code></td><td><code>package</code></td><td>an OS package, through the target's package manager</td></tr><tr><td><code>zap.apt_repo</code></td><td><code>apt_repo</code></td><td>an apt source list and its signing key</td></tr><tr><td><code>zap.script</code></td><td><code>script</code></td><td>a command gated by an idempotency <code>check</code></td></tr><tr><td><code>zap.installer</code></td><td><code>installer</code></td><td>a script fetched with <code>curl</code> and run by a shell, gated by a <code>check</code></td></tr><tr><td><code>zap.user</code></td><td><code>user</code></td><td>a Unix user: shell, home mode, SSH keys, sudo</td></tr><tr><td><code>zap.directory</code></td><td><code>directory</code></td><td>a directory at <code>path</code>, with mode and owner</td></tr><tr><td><code>zap.file</code></td><td><code>file</code></td><td>a file with inline, template, source, or remote content</td></tr><tr><td><code>zap.link</code></td><td><code>link</code></td><td>a symlink from <code>path</code> to <code>target</code></td></tr><tr><td><code>zap.service</code></td><td><code>service</code></td><td>a system service: enabled, started, stopped</td></tr><tr><td><code>zap.database</code></td><td><code>database</code></td><td>a PostgreSQL database and its role</td></tr><tr><td><code>zap.swap</code></td><td><code>swap</code></td><td>a swap file in <code>/etc/fstab</code></td></tr><tr><td><code>zap.firewall</code></td><td><code>firewall</code></td><td>default policies and allow rules</td></tr><tr><td><code>zap.verify</code></td><td><code>verify</code></td><td>detection-time assertions, with no execution of its own</td></tr><tr><td><code>zap.pipeline</code></td><td><code>pipeline</code></td><td>an ordered imperative workflow of steps</td></tr><tr><td><code>zap.build</code></td><td><code>build</code></td><td>a verified source archive, built and installed</td></tr></tbody></table><p>Each section below gives the resource's purpose, its fields, and any structure
specific to the type. In path fields, references resolve against the
operator environment, and <code>~</code> and <code>$HOME</code> resolve against the target's home.
Both happen when Zap reads or changes the machine, and the plan holds both as
written (<a>env.md</a>).</p><h3>One resource per thing</h3><p>Two resources that manage one thing would undo each other on every apply, so a
config that declares them doesn't validate; the message names both ids and the
thing. What a resource manages:</p><table><thead><tr><th>Type</th><th>Manages</th></tr></thead><tbody><tr><td><code>file</code>, <code>directory</code>, <code>link</code>, <code>swap</code></td><td>its <code>path</code></td></tr><tr><td><code>build</code></td><td>its <code>output</code> and the record beside it</td></tr><tr><td><code>apt_repo</code></td><td>its key file and its list file</td></tr><tr><td><code>user</code></td><td>the account, its <code>~/.ssh</code> directory and <code>authorized_keys</code> when <code>ssh_keys</code> is set, and its sudoers file when <code>sudo</code> is set</td></tr><tr><td><code>service</code></td><td>the service</td></tr><tr><td><code>database</code></td><td>the database (several databases may share a role)</td></tr><tr><td><code>firewall</code></td><td>the machine's firewall (a config declares at most one), and under nftables <code>/etc/nftables.nft</code></td></tr></tbody></table><p>A <code>package</code>, a <code>script</code>, an <code>installer</code>, a <code>pipeline</code>, and a <code>verify</code> manage
nothing exclusive, so the same package may be declared twice. Two resources
at one path conflict even when they declare the same thing, so a directory two
recipes both need is declared once. Paths are
compared as written, after <code>//</code>, <code>/./</code>, and a trailing <code>/</code> <code>$HOME</code> is read as <code>~</code>; two spellings that only meet on the machine (<code>~/x</code> <code>/home/ops/x</code>, a <code>..</code> component, <code>nginx</code> and <code>nginx.service</code>) aren't caught.</p><h3>URLs</h3><p>A URL in a config is <code>https://</code> with a host, and holds no <code>user:password@</code> <code>auth</code>, where it is a reference). Any other scheme is
refused, <code>http://</code> and <code>file://</code> included, when the config is read and again on
the resolved value when the URL holds a reference. For the URLs Zap itself
fetches (a <code>remote</code> file's, a <code>build</code> <code>apt_repo</code>'s <code>key_url</code>), <code>http://</code> is accepted for a loopback host
(<code>localhost</code>, <code>127.0.0.0/8</code>, <code>[::1]</code>), which is what a local mirror or a test
uses. A redirect is followed only to another <code>https://</code> URL; a fetch that has
stayed on loopback may be redirected on loopback. The URL the target fetches
(<code>installer.url</code>) is <code>https://</code> only.</p><h3>Account names</h3><p><code>username</code>, <code>groups</code>, and every <code>owner</code> and <code>group</code> <strong>name</strong>, such as <code>'deploy'</code>, not a numeric uid or gid. Zap compares ownership
against the name from <code>stat</code>, so a numeric value is rejected when the config is
read.</p><p>The name must be a portable Unix account name: a lowercase letter or <code>_</code>, then
lowercase letters, digits, <code>_</code>, or <code>-</code>, optionally ending in <code>$</code> <code>useradd</code> default on Debian and Alpine. Anything else (an uppercase letter, a
space, <code>/</code>, a comma, a backslash) is rejected there too. The name is
interpolated into <code>awk</code>, <code>usermod -aG</code>, a sudoers drop-in, and <code>/home/&lt;name></code> </p><h2><code>package</code></h2><p>An OS package, installed through the target's package manager: <strong>apt</strong> <strong>apk</strong> (Alpine). The other managers (<code>pacman</code>, <code>brew</code>) parse
but have no backend, so their packages detect as undetermined; the TypeScript
types (<code>PackageManager</code>) name only <code>apt</code> and <code>apk</code>.</p><!><ul><li><code>from</code> <code></code>. The target's <code>package_manager</code> selects the entry. A name
takes no reference; see <a>Package names</a>.</li><li><code>check</code> <code>/</code>, <code>~</code>, or <code>$HOME</code> is a path, and its references resolve; anything
else is a command, run as written, and takes no reference. With no <code>check</code>, a
package with no entry for the target's <code>package_manager</code>, or a target that
declares none, holds (<code>undetermined</code>).</li></ul><p>Installs are batched, after an automatic cache-update step. A package that waits
on another resource that waits on a package installs in a later batch
(<code>batch-install-&lt;manager>-2</code>, …), after that resource. Detection is by
existence through the manager's query: a package held back, or installed for any
architecture, is installed. A query that fails (the database unreadable, the
tool missing) holds the package as undetermined rather than reading it missing.</p><h3>Package names</h3><p>A name is one word in the manager's syntax: a letter or a digit, then letters,
digits, and <code>+ . _ - = ~ : / @</code>, not ending in <code>-</code>. Zap writes it into the
manager's command line unquoted, so a space or a shell character is refused.
The form decides what reads as installed:</p><table><thead><tr><th>Form</th><th>Manager</th><th>Installed when</th></tr></thead><tbody><tr><td><code>name</code></td><td>apt, apk</td><td>the query finds it, at any version</td></tr><tr><td><code>name=version</code></td><td>apt</td><td>it is at exactly that version, epoch and revision included. apt upgrades to it and refuses to downgrade to it, which fails the step.</td></tr><tr><td><code>name/suite</code></td><td>apt</td><td><code>name</code> is installed; the suite chooses where a first install comes from</td></tr><tr><td><code>name:arch</code></td><td>apt</td><td>it is installed for that architecture; a package built for every architecture (<code>all</code>) counts as the target's own</td></tr><tr><td><code>name=version</code>, <code>name~version</code></td><td>apk</td><td>the installed version matches, as apk compares them</td></tr><tr><td><code>name@tag</code></td><td>apk</td><td><code>name</code> is installed; the tag chooses where a first install comes from</td></tr></tbody></table><p>A version and a suite together name no package apt knows. Refused, because the
query would never find the package installed or the form isn't one word:</p><ul><li>apt: an empty version (<code>name=</code>) or architecture (<code>name:</code>); <code>name:any</code> <code>name:native</code>, which apt resolves to an architecture and dpkg records no
package under; <code>name:all</code>, which apt reads as the native architecture while
dpkg records <code>all</code> only for a package built for every one (name the
architecture, or none); an architecture that isn't one word of lowercase
letters, digits, and <code>-</code>.</li><li>apk: <code>name>=1.2</code>, <code>!name</code>, <code>.name</code>; a version operator with nothing after it
(<code>name=</code>, <code>name~</code>, <code>name==</code>, <code>name@tag=</code>), which apk's query reads installed
whether or not it is and <code>apk add</code> refuses.</li></ul><p>A trailing <code>+</code> is part of the name, since Debian has packages named so
(<code>memtest86+</code>). apt's own <code>name+</code> install marker on a package with no <code>+</code> </p><h2><code>apt_repo</code></h2><p>An apt repository: a GPG signing key plus a sources-list entry. Zap installs
the key, writes the <code>.list</code> file, and injects <code>signed-by=&lt;key_path></code> into the
source line automatically, so the key and the repo can't drift apart.</p><!><ul><li><code>key_url</code> (required): the URL Zap fetches the GPG signing key from
(<a>URLs</a>). It may carry a reference.</li><li><code>key_blake3</code> (optional): the key's pin, the blake3 of its bytes, 64 lowercase
hex. Without it the pin is tracked in <code>zap.lock</code> <a>lock.md</a>).</li><li><code>source</code> (required): the <code>deb</code> or <code>deb-src</code> source line. <code>signed-by=</code> is
injected from <code>key_path</code>.</li><li><code>key_path</code> <code>/usr/share/keyrings/&lt;id>.asc</code>.</li><li><code>list_file</code> (optional): the <code>.list</code> <code>/etc/apt/sources.list.d/&lt;id>.list</code>. The list is installed whole, mode <code>644</code>.</li></ul><p><code>key_path</code> and <code>list_file</code> take no reference; <code>key_url</code> may carry one. Each of
the two paths is absolute and holds no whitespace and none of <code>"</code>, <code>$</code>, a
backtick, or <code>\\</code>.</p><p><code>source</code> is written through a shell with <code>/etc/os-release</code> <code>deb … $VERSION_CODENAME main</code> resolves to <code>bookworm</code>, <code>noble</code>, and so on, on
the target. <code>key_path</code> <code>list_file</code> is passed literally; <code>key_url</code> is fetched by Zap on the operator's
machine and never reaches the target. The detector resolves <code>source</code> <code>source</code> takes no reference.</p><p>The key is pinned content, like a <code>remote</code> file's. Zap fetches it on the
operator's machine, checks the bytes against the pin, and installs those bytes
whole at <code>key_path</code>, mode <code>644</code>, owned by <code>root:root</code>: staged beside the key,
checked against their SHA-512, and renamed over it, so the live key is only
ever replaced by the pinned bytes. A fetch whose bytes aren't the pin's fails
the change before anything on the target is touched, naming both digests:</p><!><p>Detection reads the key and compares its blake3 with the pin: a key that
isn't the pinned bytes drifts (<code>signing key differs from its pin</code>), and the
apply installs the pinned one. A rotated upstream key is not drift until the
pin moves: <code>zap update &lt;id></code> fetches the key again and advances the pin, which
shows in the lock's diff. A key with no pin yet is held (<code>undetermined</code>) by the
read-only commands, a dry <code>apply</code> <code>zap.lock</code> before it runs, as for any tracked content. A <code>key_path</code> that is a
symbolic link, a hard link, or not a regular file, or a key over 1 MiB, is held
too: its bytes aren't compared.</p><h2><code>script</code></h2><p>An imperative command guarded by an idempotency <code>check</code>. Zap runs <code>check</code> first.
An exit code of 0 means the script is already applied and <code>run</code> is skipped.
Otherwise <code>run</code> executes.</p><!><ul><li><code>check</code> (required): a command whose exit 0 means "already applied", which
skips <code>run</code>.</li><li><code>run</code> (required): the command run when <code>check</code> fails.</li><li><code>cwd</code> (optional): the working directory for <code>check</code> and <code>run</code>. An absolute
path, taken as written: a reference is rejected when the config is read, and
a <code>~</code> or a relative path by the structural gate.</li><li><code>env</code> (optional): extra environment for the whole of <code>check</code> and <code>run</code>.
Values resolve references and can hold any byte but NUL (and the two
characters Zap marks a reference with, U+FDD0 and U+FDD1), so <code>env</code> is how a
script takes a value with a <code>'</code> <code>__zap_</code>.</li></ul><p>The <code>check</code> carries the whole idempotency contract. Make it precise, or the
script runs on every apply.</p><p><code>cwd</code> and <code>env</code> apply to both commands, the same way on a local target and over
SSH: Zap enters <code>cwd</code>, exports <code>env</code> for the whole command (every command of a
compound sees it), then runs your text on a line of its own. The plan shows
them, and the <code>check</code>, above the command:</p><!><p>A <code>check</code> that can't enter <code>cwd</code> reads as not applied, like any failing check, so
a script whose <code>cwd</code> another resource creates converges in one apply. A <code>run</code> <code>sudo</code> inside either
command resets the environment by default, so <code>env</code> doesn't cross it.</p><h2><code>installer</code></h2><p>Software installed by running a downloaded script, the <code>curl … | sh</code> pattern,
gated by a <code>check</code> so it runs only once. Zap fetches the script whole first and
hands it to the shell only if the fetch succeeded and the script isn't empty, so
a failed download fails the step and nothing runs.</p><!><ul><li><code>url</code> (required): the install script's <code>https://</code> URL (<a>URLs</a>), piped
into <code>shell</code>.</li><li><code>check</code> (required): a path, absolute or beginning with <code>~</code> or <code>$HOME</code>, tested
for existence to confirm installation.</li><li><code>shell</code> (optional): the command the script is piped into (default <code>sh</code> <code>script</code>'s <code>run</code>, so <code>bash -s -- --yes</code> passes arguments.</li></ul><p>An installer executes remote code on the target, so prefer a pinned, trusted
URL. For content that should be verified and pinned, a <code>build</code> or a <code>file</code> <code>remote</code> content is the stronger choice.</p><h2><code>user</code></h2><p> <code>useradd -m -d /home/&lt;username></code>, so the home is <code>/home/&lt;username></code> whatever the
distro's default. Zap then detects and reconciles
each managed attribute independently. An attribute left unset is unmanaged: Zap
neither sets nor reverts it.</p><p>Zap manages a user's home as <code>/home/&lt;username></code>: the paths <code>home_mode</code> <code>ssh_keys</code> act on are derived from the name, not read from the machine. The
cases where that would be wrong fail loudly instead:</p><ul><li>A <code>user</code> with <code>username: 'root'</code>, whose home is <code>/root</code>, is <strong>rejected by the
structural gate</strong> before any run, whatever it declares. Manage root's files
with <code>file</code> and <code>directory</code> resources.</li><li>An existing account whose home in <code>/etc/passwd</code> is anything else, or that has
none there, is <strong>held</strong> (<code>undetermined</code>) when the user declares <code>home_mode</code> <code>ssh_keys</code>, and the reason names the home it found:<!><p>An account that doesn't exist yet has no <code>/etc/passwd</code> home to hold it: Zap
creates it.</p></li><li>What is at <code>/home/&lt;username></code> is read too, without following a link, whether
the account exists or not. <code>useradd</code> leaves a directory already there as it
was, owned by root typically, and copies no skeleton files into it:<ul><li>when Zap creates the account, the creation gives the directory
itself, not what it holds, to the user and its login group after <code>useradd</code> <code>sudo chown -h -- 'deploy:' '/home/deploy'</code>, a no-op when <code>useradd</code> made
the directory;</li><li>for an existing account, a directory the user owns or root owns is as
declared and keeps its owner, so a home sshd's <code>ChrootDirectory</code> needs root
to own stays root's;</li><li>a directory owned by any other uid, a live account's or one no account
has, holds the user, existing or not;</li><li>a symbolic link at <code>/home/&lt;username></code> holds the user and is not followed:
Zap acts through no link it didn't make, so a layout that links the home
elsewhere declares neither <code>home_mode</code> nor <code>ssh_keys</code>; anything else that
isn't a directory holds too;</li><li>a <code>/home</code> that is missing, or that the connecting user can't search,
holds the user, naming <code>/home</code>, rather than reading as nothing there.</li></ul><!><p>A user that declares neither <code>home_mode</code> nor <code>ssh_keys</code> isn't read for its
home.</p></li></ul><!><ul><li><code>username</code> (required): the Unix username to manage. It must be a portable
account name; see <a>Account names</a> <code>groups</code> entries follow the same rule.</li><li><code>shell</code> (optional): the login shell, such as <code>/bin/bash</code>. The system default
applies when unset. It takes no reference.</li><li><code>home_mode</code> (optional): the octal mode for the home directory, such as <code>711</code>.</li><li><code>ssh_keys</code> (optional): the SSH <code>authorized_keys</code> <code></code> or <code></code>, never both: an
object with both is rejected before any run. A <code>keys</code> list needs at least one
key, and no entry may be blank. See <a>SSH keys</a>.</li><li><code>sudo</code> (optional): the user's sudo grant. See <a>Sudo</a>.</li><li><code>groups</code> <code>['docker', 'postgres']</code>. It is additive: listed groups are added
(<code>usermod -aG</code>) and groups not listed are left untouched. The primary and
system groups are never stripped. Names only, like <code>owner</code>.</li></ul><h3>SSH keys</h3><p><code>ssh_keys</code> is authoritative. Zap writes <code>authorized_keys</code> to exactly the
declared set and detects drift by comparing the file's content. A key added out
of band is removed on the next apply, and a rotated or removed key is applied
again.</p><p>A key is installed as written and takes no reference; one is rejected
before any run. An entry is one key on one line: an entry that ends in a line
break doesn't validate. A config reads no file but its imports, so for keys that
differ per environment, have the config import them from a module in the project
(<code>export const OPS_KEYS = ['ssh-ed25519 AAAA… ops'];</code>).</p><p>For <code>copy_from</code>, the source user's <code>authorized_keys</code> is the desired content. If
it can't be read, the user is applied again and does not read converged.</p><p>Zap gives the account its <code>~/.ssh</code> (mode <code>700</code>, owned by the user; a symlink
there is refused, not followed) and then writes <code>authorized_keys</code> <strong>as that
user</strong>, mode <code>600</code>, so nothing the user plants in its own <code>.ssh</code> can redirect
the write anywhere the user couldn't already write. A <code>copy_from</code> source is read
as the source user at apply. Other files in <code>.ssh</code> are left as they are.</p><p>Setting <code>ssh_keys</code> also normalizes the account's <code>/etc/shadow</code> <code>*</code>, which means no password and <em>not</em> locked. This is authoritative too: any
other value drifts and converges back to <code>*</code>. That covers:</p><ul><li>a <code>!</code> lock. <code>useradd</code> leaves a passwordless account locked, and Alpine's sshd
refuses pubkey login to a locked account ("account is locked").</li><li>an empty field, which allows passwordless login and is a security hole;</li><li>a set password.</li></ul><h3>Sudo</h3><ul><li><code>'nopasswd'</code> or <code>'password'</code> grants sudo for all commands.</li><li><code></code> restricts
the grant to the listed commands. A spec is written into the file as declared
and takes no reference. The list can't be empty, and a spec can't be blank or
hold a control character (a tab counts): each is rejected when the config is
read. For a grant of every command, write the mode alone. A spec is sudoers
text, so a <code>,</code> in one ends a command and begins another.</li><li><code>false</code> removes the user's sudoers file.</li><li><code>true</code> is rejected at parse. It grants nothing, and would otherwise read as a
removal.</li></ul><p>The sudoers file is installed at mode <code>440</code> only after <code>visudo -c</code> accepts it;
a file <code>visudo</code> rejects is never installed, and the old one stays.</p><h2><code>directory</code></h2><p>A directory at <code>path</code>, with optional managed permissions.</p><!><ul><li><code>path</code> (required): the directory path, absolute or under <code>~</code>. It may carry a
reference, and the value it resolves to is held to the same rule.</li><li><code>mode</code> (optional): the octal mode, such as <code>'755'</code>, <code>7777</code> at most.</li><li><code>owner</code> (optional): the owner.</li><li><code>group</code> (optional): the group.</li></ul><p>Zap makes the directory and any missing parents. Each one it makes, the
directory itself included, takes the owner and group of the nearest directory
that was already there, and the mode a plain <code>mkdir</code> gives; then the declared
mode, owner, and group are set. So an owner or group left unset is inherited
from above, and an existing directory keeps its own. Anywhere below a directory
with its sticky bit set or that every account may write (<code>/tmp</code>, <code>/var/tmp</code> <code>/dev/shm</code>), however deep, on the path as written or where its links lead,
nothing is inherited: what Zap makes there is the writer's. On a local target,
directories that take another account's owner, or a group you aren't in, are
made through <code>sudo</code>.</p><p>With a managed mode, owner, or group, a symlink at <code>path</code> reads as drift and
fails the change: Zap sets a directory's attributes on the directory itself and
never through a link. Use <a><code>link</code></a> for a symlink.</p><h2><code>file</code></h2><p>A file with managed content and optional permissions. Content comes from one of
these sources, selected by <code>content.type</code>: <code>inline</code>, <code>template</code>, <code>source</code> <code>remote</code>.</p><p> <code>mkdir -p</code> <a><code>directory</code></a>), and the mode a plain <code>mkdir</code> gives; an existing one
is left as it is. A separate <code>directory</code> resource is only needed when the directory
itself wants a managed mode or owner.</p><p>A <code>file</code> is a regular file, written whole: Zap stages the content under a new
name beside it (<code>.zap.XXXXXX</code>, mode <code>600</code> until a declared mode is set), checks
over SSH or <code>sudo</code> that the bytes that arrived are the bytes it sent, sets the declared owner and mode on that staged file, and
renames it into place. So the file never exists at its path with partial
content or the wrong mode, a mode or owner drift rewrites it, and a symlink at
the path is replaced by the file, not followed (a symlink to a directory fails
the change on Alpine; with a managed mode, owner, or group, a symlink there
reads as drift). Use <a><code>link</code></a> for a symlink.</p><p>A mode, owner, or group the file leaves unset is kept: a rewrite gives the new
content the owner and group of the file it replaces, and its mode without any
set-id or sticky bit. A new file takes its directory's owner and group, and the
mode a plain create gives (<code>0666</code> less the writer's umask). A symlink at the
path, or a file with a second name (a hard link), keeps nothing; the file that
replaces it is the writer's. Nothing is kept anywhere below a directory with its
sticky bit set or that every account may write (<code>/tmp</code>, <code>/var/tmp</code>, <code>/dev/shm</code>),
however deep, on the path as written or where its links lead: anyone could have
put what is there, or made a directory or a link on the way, so the file is the
writer's.</p><p> <code>file</code> that leaves <code>mode</code> unset over such a file fails the change, with the file
as it was, asking for a declared <code>mode</code>. Zap reads the list with <code>getfacl</code>, else
from the <code>+</code> GNU <code>ls -l</code> prints after the mode; a target with neither, such as
stock Alpine (BusyBox <code>ls</code>, no <code>acl</code> package), can't show one, and there the mode
is kept. On a local target,
keeping an owner or group you can't give, such as another account's file or a
new file in a directory root owns, goes through <code>sudo</code>.</p><p>Declare <code>mode</code>, <code>owner</code>, and <code>group</code> on any file whose content the directory's
owner or group must not read. Without them, a file written into a directory
another account can write can end up readable by that account: it takes that
account's directory's owner and group, or the owner, group, and mode of the file
that account planted at the path. A declared owner and group don't replace a
planted file's mode, so without a <code>mode</code> the content can land readable by
everyone (<a>security.md</a>).</p><!><ul><li><code>path</code> (required): the target path. It may carry a reference and <code>~</code>.</li><li><code>content</code> (required): the content source. See <a><code>content</code></a>.</li><li><code>mode</code> (optional): the octal mode, such as <code>'644'</code>.</li><li><code>owner</code> <a>Account names</a>.</li><li><code>group</code> (optional): the group, as a group name and not a numeric gid.</li><li><code>triggers</code> (optional): ids of <code>service</code> resources notified when this file
changes; naming any other kind doesn't validate. This is
the push side of the trigger model; see <a><code>service</code></a>.</li><li><code>validate</code> <code>sudo nginx -t</code> (exported as <code>NGINX_VALIDATE</code> from <code>recipe_nginx.ts</code> <a>Validated writes</a>.</li></ul><h3>Validated writes</h3><p>With <code>validate</code> set, apply snapshots the file (its bytes, mode, and owner, read
through one open descriptor and held in memory: as root over SSH, and locally
as you, escalating when refused), writes, then runs the
command against the file in place. A symlink at the path, anything there that
isn't a regular file, and a file over 16 MiB can't be snapshotted, so the change
fails before the write. If the check fails, the snapshot goes back as a regular
file with the owner and group the old content had, and its mode without any
set-id or sticky bit the declared <code>mode</code> doesn't carry; a file that didn't
exist is removed; and the change fails. So any service the file <code>triggers</code> is never reloaded onto the
bad config. A write that fails before installing leaves the file as it was, and
restores nothing.</p><p> <code>nginx -t</code> can't check a site file on its own.</p><!><p>What it doesn't cover:</p><ul><li><strong>One file at a time.</strong> Each file is checked against whatever else is on disk.
An edit that has to land in two files at once (renaming a zone one file defines
and another uses) fails the first file's check and rolls it back. Stage the
edit across applies: add the new name, switch the user, drop the old.</li><li><strong>Not yet active.</strong> The check only sees what the parent config loads. An nginx
site in <code>sites-available/</code> isn't checked until its <code>sites-enabled/</code> link exists,
so on a fresh host the first real check is the reload.</li><li><strong>The write-to-restore window.</strong> The rejected content is on disk for one
command's round trip. A run killed inside it leaves that content in place, and
detection reads it as converged, since the bytes match what was declared.</li></ul><p>The last two, plus hand edits on the host, are what a <a><code>verify</code></a> <code>zap deploy</code>'s preflight refuses to ship over it:</p><!><p><code>validate</code> is apply-time behavior, not desired state: detection doesn't read
it, and changing it alone plans no change. It is still part of the declaration:
the last-run report's hash covers it, and so does <code>plan_hash</code> whenever the file
has a change in the plan. The lock's <code>config_hash</code> leaves it out. It is for text config
(<code>inline</code>, <code>template</code>, <code>source</code>), and is rejected on <code>remote</code> content and when
blank.</p><h3><code>content</code></h3><p>The content source is discriminated on <code>type</code>.</p><p><strong><code>inline</code></strong>: literal content, written verbatim.</p><ul><li><code>type</code> (required): <code>'inline'</code>.</li><li><code>content</code> (required): the file's content, installed as declared. It takes
no reference.</li></ul><p><strong><code>template</code></strong>: a <code></code> template with per-variable substitution.</p><ul><li><code>type</code> (required): <code>'template'</code>.</li><li><code>template</code> (required): the template body, with <code></code> placeholders. A
placeholder is a variable's name between the braces and nothing else; braces
around anything that isn't a name (<code></code>) are text.</li><li><code>vars</code> (optional): the values substituted for each <code></code> <code>vars</code> map. A value with no kind is substituted as text, so it has to be safe
where it lands: in a file a shell or systemd's <code>EnvironmentFile=</code> reads, a
value holding a <code>'</code> ends its quoting.</li><li><code>kinds</code> (optional): the kind of value a variable must render to, by its
name. Each key names a variable in <code>vars</code>. A variable not named here declares
no kind: a reference in its value is still held to the <code>text</code> rule, and a
value written out is substituted unchecked.</li></ul><p>Placeholders and variables match one for one: a <code></code> whose name is
letters, digits, and <code>_</code> (not starting with a digit) and that has no variable of
that name doesn't validate, and neither does a variable no placeholder names, so
a misspelled name is caught in either direction. The body is substituted in one
pass and a value is never read again, so a value may hold <code></code> as text; that
is also how a literal <code></code> is written.</p><p>A reference's value can't hold a line break (CR or LF) or a NUL: the files a
template makes are read a line at a time, and a line break in a value would add
a line of its own (another variable in an environment file, another directive
in a config). Detection holds the file and names the variable, and a wetrun is
refused before anything changes.</p><p>Within its line, what a value may hold is the file's grammar: a <code>;</code> or a <code></code> <code></code> ends the directive or the block. A kind
holds a variable's whole rendered value to a form whose alphabet has none of
that:</p><table><thead><tr><th>Kind</th><th>A value is</th></tr></thead><tbody><tr><td><code>text</code></td><td>any one line: no line break, NUL, or reference delimiter; every kind keeps this rule, and a reference's value is held to it with no kind declared</td></tr><tr><td><code>hostname</code></td><td>dot-separated labels of ASCII letters, digits, and <code>-</code>, each 1 to 63 bytes, no leading or trailing <code>-</code>, at most 253 bytes; no trailing dot, wildcard, or <code>_</code></td></tr><tr><td><code>port</code></td><td>a decimal number from 1 to 65535, with no sign or leading zero</td></tr><tr><td><code>path</code></td><td>an absolute path whose names are ASCII letters, digits, <code>.</code>, <code>_</code>, <code>-</code>, <code>+</code>, and <code>@</code>, with no empty, <code>.</code>, or <code>..</code> name</td></tr><tr><td><code>email</code></td><td>a local part of ASCII letters, digits, <code>.</code>, <code>_</code>, <code>%</code>, <code>+</code>, and <code>-</code> (no leading, trailing, or doubled <code>.</code>), an <code>@</code>, and a <code>hostname</code></td></tr><tr><td><code>env_value</code></td><td>a value inside single quotes in an env file: <code>text</code> with no <code>'</code></td></tr></tbody></table><!><p>A value written out is checked when the config is read. One carrying a
reference is checked once it resolves: detection holds the file, and a wetrun
is refused before anything changes, naming the variable and its kind, never the
value. The nginx site and env recipes return their templates whole, with the
kinds of the variables they place (<a>recipes.md</a>).</p><p><strong><code>source</code></strong>: content copied from a file already on the target at apply time.</p><ul><li><code>type</code> (required): <code>'source'</code>.</li><li><code>path</code> (required): a path on the target, absolute or under <code>~</code>. It may carry
a reference.</li></ul><p>The source is read as root over SSH, byte for byte, so a binary file copies
whole. It must be a regular file of its own at that path: a symbolic link there
is never read through, and neither is a directory, a device, or a fifo. Detection
holds the resource on any of them, and apply refuses them with nothing written.
The bytes are held in memory while they are written, so a source larger than
16 MiB is refused at apply.</p><p><strong><code>remote</code></strong>: content fetched from a URL, content-addressed and verified the
same way a <a><code>build</code></a> source is.</p><ul><li><code>type</code> (required): <code>'remote'</code>.</li><li><code>url</code> (required): the fetch location (<a>URLs</a> <a>lock.md</a>.</li><li><code>extract</code> (optional): how the bytes are materialized. <code></code> is the
default; <code></code> extracts an
archive. <code>strip_components</code> lives inside the tar form (beside <code>none</code> it is
rejected), and strips leading path components: <code>1</code> flattens a tarball's single top
directory.</li><li><code>auth</code> (optional): a bearer credential for a private byte host, resolved at
the IO boundary and never hashed. See <a>Remote auth</a>.</li><li><code>blake3</code> (optional): a vendored content pin. Present, the file pins itself;
absent, it tracks through <code>zap.lock</code> <a>lock.md</a>.</li></ul><p><strong>How a remote file is detected.</strong> An unextracted file by digest against the
pinned bytes, an extracted one through its <code>.zap_remote_hash</code> <a>detection.md</a>.</p><p><strong>Placement and ownership.</strong> <code>none</code> <code>/opt/zig</code>) runs under <code>sudo</code>. When <code>extract</code> produces a directory tree, a
declared <code>mode</code>, <code>owner</code>, or <code>group</code> applies to the <strong>top-level</strong> destination
only (a symlink there holds the resource, and nothing is extracted through it).
The extracted contents below it belong to the extracting user, which is root
when the extract escalated, whatever owners the archive records, and carry no
set-id bit on a file and no group or world write bit. The archive is extracted
into a private directory beside the destination, which then takes the
destination's name; a failed extraction leaves the destination as it was. A new
pin replaces the old tree whole, and the new one gets the owner, group, and
mode the old one had (without a set-id or sticky bit) before it takes the name,
so what the resource leaves unset there is kept, and a failure to set them
leaves the old tree in place. Below a directory with its sticky bit set or that
every account may write, nothing is kept, as for a <a><code>file</code></a>: the new tree
is the extracting user's, at the mode <code>mkdir</code> gives it. A replaced tree that
has a POSIX access list (ACL), a default one included, fails the change with the
old tree in place, whatever <code>mode</code> declares; remove the list (<code>setfacl -b</code>) to
let Zap replace it. The archive never sets the destination's mode, whatever it
records for its top directory: a new destination keeps what <code>mkdir</code> gives it. Zap replaces only a tree it extracted (one holding its sentinel) or an
empty directory; a destination holding anything else holds the resource
(<code>undetermined</code>), and nothing is extracted into it. If the whole tree needs a
specific owner, apply it with a <code>script</code> running a recursive <code>chown</code>.</p><p>The swap needs room for the old and the new tree at once, and the archive sits
on the target three times while it extracts: the upload in a private directory
under <code>/tmp</code>, the copy the extraction checks and reads, on the destination's
parent filesystem, and the tree it extracts. A run that is killed
can leave a mode <code>0700</code> <code>.&lt;name>.zap-XXXXXX</code> <code>NAME_MAX</code> can't be extracted.</p><h4>Remote auth</h4><p>For a private byte host, attach a bearer credential. Its token is typically a
reference, resolved on the operator side at fetch time. It is never
written to the content hash, and an empty resolution is an error, not a bogus
request.</p><!><h2><code>link</code></h2><p>A symbolic link at <code>path</code> pointing to <code>target</code>.</p><!><ul><li><code>path</code> (required): the symlink path. It may carry a reference and <code>~</code>.</li><li><code>target</code> (required): what the link points to, resolved the same way.</li></ul><p>A regular file sitting at <code>path</code> reads as absent and is replaced by the link. A
directory there also reads absent, but the step fails rather than putting the
link inside it: move the directory, or point the resource at another path.</p><h2><code>service</code></h2><p>A system service managed through the target's service manager (<strong>systemd</strong> <strong>OpenRC</strong>). It controls whether the service is enabled at boot and whether it
is running, and it can restart or reload in response to other resources
changing. That is the pull side of the trigger model; <a><code>file</code></a> <code>triggers</code> is the push side.</p><!><ul><li><code>service</code> (required): the service name, as the target's service manager knows
it. It takes no reference, and is one word: a letter or a digit, then letters,
digits, and <code>_ . @ : -</code> (<code>nginx</code>, <code>getty@tty1.service</code>). Zap writes it into
the manager's command line unquoted, so a systemd name escaped with a
backslash isn't accepted.</li><li><code>enabled</code> (optional): whether the service is enabled at boot (default <code>true</code>).</li><li><code>running</code> <code>rc-service &lt;svc> zap</code>, since a plain start of a crashed service does nothing. OpenRC reads a
service as crashed when the process its pidfile names isn't running, so a
daemon still running under a stale pidfile gets a second copy beside it.</li><li><code>restart_on</code> (optional): resource ids whose change triggers a restart of
this service: <code>systemctl try-restart</code> <code>rc-service --ifstarted &lt;svc> restart</code> on OpenRC.</li><li><code>reload_on</code> (optional): resource ids whose change triggers a reload of this
service. That is <code>try-reload-or-restart</code> <code>rc-service --ifstarted &lt;svc> reload</code> on OpenRC, where a service that can't
reload fails the step.</li></ul><p> <code>daemon-reload</code>), never its enable or start again. A trigger on a service
declared <code>running: false</code> (its <code>restart_on</code> / <code>reload_on</code> <code>triggers</code> naming it) is a structural error: it could never act.</p><p>The target must declare a <code>service_manager</code>. The structural gate rejects, in
every command, a config with <strong>service intent</strong> on a target that declares none,
and doesn't guess <code>systemctl</code> on a host that may run OpenRC. Service intent is any of:</p><ul><li>a <code>service</code> resource;</li><li>a <code>file</code> with <code>triggers</code>;</li><li><code>deploy.service</code>.</li></ul><p>A declared manager with no backend (<code>launchd</code> <code>undetermined</code>, and their verbs plan as notes, not commands. The TypeScript types
(<code>ServiceManager</code>) name only <code>systemd</code> and <code>openrc</code>.</p><h3>Pending triggers</h3><p>A trigger fires when one of its sources changes in the current plan. On its own,
a failed reload would be lost: the next plan reads the source as converged (its
bytes match) and the service as running (on the old config).</p><p>So Zap keeps a record on the target. Before the first source of a triggered
service runs, apply writes a marker to <code>/var/lib/zap/pending/&lt;service></code> holding
the owed action. It removes the marker only after the service's own change
completes. If the reload fails, or the run dies anywhere in between, the marker
stays, and the next plan fires the action again:</p><!><p>A pending restart outranks a reload fired this run. The markers are read live,
as root, on every plan for a config that declares a trigger, and a marker for a
service the config doesn't manage is reported as a warning. A marker directory
that can't be read fails the plan rather than reading as owing nothing. Zap
gives <code>/var/lib/zap</code> and <code>pending/</code> mode <code>755</code> and each marker <code>644</code>, whatever
the umask. The service's change clears its marker whether or not the service was
running: a stopped service owes nothing, since it starts on the new state.</p><p>Zap keeps its state in <code>/var/lib/zap</code>, and refuses the declarations that would
manage it. A structural error is any resource whose path is at or under it as
written (<code>.</code> and <code>..</code> taken as written), a home-rooted path with a <code>..</code> <code>link</code> whose target is <code>/var/lib/zap</code>, under it, or a directory
above it (<code>/</code>, <code>/var</code>, <code>/var/lib</code> <code>link</code> placed at one of those directories above it (which it would replace),
and a <code>deploy.path</code> there. A path or link target that reaches it only once a
reference or <code>~</code> resolves holds the resource in detection and is refused by the
wetrun. What isn't a declared path isn't checked: the commands a <code>script</code> <code>pipeline</code>, <code>installer</code>, or <code>build</code> runs can write anywhere, and a symbolic
link already on the target that leads into <code>/var/lib/zap</code> is followed like any
other directory link.</p><p>The record is written first, so the guarantee is at-least-once. A run that fails
after the marker but before any source changed fires one reload or restart it
didn't strictly need. It never drops one it did.</p><p>A held service, whether detection can't read it or it is held behind another,
gets no marker, so each source whose change would trigger it is held too, with
the reason "would restart (or reload) the service, which is held". Running the
source alone would owe a restart nothing records. The next plan that can run the
service plans both.</p><h2><code>database</code></h2><p>A <strong>PostgreSQL</strong> database and its owning role. Zap creates the role and database
idempotently, sets the database's owner back to the role when it has drifted, and manages the declared <code>pg_hba.conf</code> auth rules.
It never restarts PostgreSQL, so the target needs no <code>service_manager</code> for it.</p><!><ul><li><code>engine</code> (required): <code>'postgresql'</code>.</li><li><code>database_name</code> (required): the database to create.</li><li><code>username</code> (required): the role to create, which owns the database.</li><li><code>auth</code> (optional): the <code>pg_hba.conf</code> <a>Database auth</a>.</li></ul><p>Both names, and each <code>auth.hosts</code> entry, are written into a <code>pg_hba.conf</code> line
as they are, so none may hold whitespace, <code>#</code>, <code>"</code>, <code>,</code>, or a control character. A name doesn't begin
with <code>+</code>, <code>@</code>, <code>/</code>, or <code>-</code>, a database isn't named with a word <code>pg_hba.conf</code> <code>all</code>, <code>sameuser</code>, <code>samerole</code>, <code>samegroup</code> <code>replication</code>), and a role isn't named <code>all</code>. The rule holds for the value a
reference resolves to as well: one that breaks it holds the resource.</p><p> <code>username: zap.env('USER')</code>. A shell-style <code>username: '$USER'</code> would never resolve.</p><h3>Database auth</h3><ul><li><code>hosts</code> (required in <code>auth</code>): the client addresses a rule admits, each an IP
address with its prefix length (<code>'127.0.0.1/32'</code>, <code>'::1/128'</code>), at least one.
A keyword (<code>all</code>, <code>samehost</code>, <code>samenet</code>) or a host name is refused, as written
and as a reference resolves. A <code>database</code> with no <code>auth</code> writes no rule.</li><li><code>method</code> (optional): the <code>pg_hba</code> <code>'scram-sha-256'</code>). A rule Zap writes is a plain TCP <code>host</code> line with no
options, so a method that can't work on one is refused: <code>'trust'</code>, since a
trusted TCP rule lets any account on the machine, any service among them,
connect as the role with no credential; <code>'peer'</code>, which PostgreSQL accepts
only on a Unix-socket (<code>local</code>) line, the route a database with no <code>auth</code> <code>'cert'</code>, accepted only on a <code>hostssl</code> line; <code>'ldap'</code> <code>'radius'</code>, which need options Zap doesn't write; and <code>'sspi'</code> and <code>'bsd'</code>,
which PostgreSQL doesn't build on Linux.</li></ul><p>With no <code>auth</code>, the role is reached the way the stock <code>pg_hba.conf</code> allows a
local account: over the Unix socket, by the OS account of the same name
(<code>local all all peer</code> on Debian, and on Alpine once <code>alpine_postgres_setup</code> has
initialized the cluster). A service running as that account
connects with <code>postgres://&lt;role>@/&lt;database>?host=/run/postgresql</code> and needs no
password.</p><p>Each rule is a <code>host</code> line in the <code>pg_hba.conf</code> the server reports. A missing
rule is inserted once, above the first <code>host</code>-type record (indented ones
included), or appended when the file has none, so it takes precedence over the
rules already there. Detection only asks whether each rule's line is present,
anywhere in the file: the rest of the file isn't judged. A rule already there
below a broader one that matches first (a <code>host all all 0.0.0.0/0 trust</code> <code>trust</code> line, a duplicate, or any other rule of the file's own is neither
reported nor removed. Review a <code>pg_hba.conf</code> Zap didn't write. The rewrite runs as the <code>postgres</code> <code>pg_hba.conf</code> owned by anyone else is left alone and the step fails saying so.
The file is replaced by rename, keeping its group and mode; if the rewritten
copy isn't the original plus that one line, Zap leaves the file alone and the
step fails. A rule Zap added is put in force by reloading the server's
configuration (<code>SELECT pg_reload_conf()</code>, as <code>postgres</code>); a rule already there
reloads nothing. Before the reload the step reads <code>pg_hba_file_rules</code> <code>error</code> <code>pg_conf_load_time()</code> <code>postgresql.conf</code> the server can't parse keeps that time from moving, so the
step fails then too, saying so. A reload the server doesn't confirm, a file it
can't parse, or a load time that doesn't move fails the step with the rule in
the file, and the next run's plan reads it present and reloads nothing: fix the
file the server can't parse, then reload by hand
(<code>sudo -u postgres psql -c 'SELECT pg_reload_conf()'</code>) once the server can. Zap
reads only that one file: a rule
inside an <code>include</code>d file isn't seen, and an <code>include</code> above the first <code>host</code> </p><h2><code>swap</code></h2><p>A swap file, recorded in <code>/etc/fstab</code>.</p><!><ul><li><code>size</code> (required): the swap size, such as <code>'2G'</code>, used when the file is
created. It is not compared afterwards: resizing means removing the file by
hand first.</li><li><code>path</code> (optional): the swap file path (default <code>/swapfile</code>): absolute, with
no whitespace, since it is a field of an <code>/etc/fstab</code> <code>~</code>-expanded and takes no reference.</li></ul><p>A swap file that drifted is repaired part by part: an active one isn't allocated,
formatted, or enabled again, and one already in <code>/etc/fstab</code> isn't listed again,
so an active swap file missing from <code>/etc/fstab</code> is only listed. One that isn't
active is allocated again before it is formatted, so a short file a full disk
left behind is made whole.</p><p>Before the file is allocated, formatted, and enabled, as root, its path is
checked: a symbolic link there is refused, since <code>mkswap</code> would format whatever
it points at, and so is any directory on the way to it, up to <code>/</code>, as declared
and as it resolves, that root doesn't own or that a group or other account can
write, where someone else could put a link at the path, or re-point a directory
above it, between the check and the format. The refusal names the path, the
directory, and the reason, and nothing is made.</p><p>Adding the entry rewrites <code>/etc/fstab</code> whole: the table as it reads plus the
entry, installed by rename with the table's mode kept and <code>root</code> as its owner.
A table the connecting user can't read fails the step with nothing written, and
so does one with a POSIX access list (ACL), whose mode can't be kept
(<a><code>file</code></a>); remove the list (<code>setfacl -b /etc/fstab</code>) to let Zap add the
entry. An
edit someone else
makes between the read and the rename is lost, and a symlinked <code>/etc/fstab</code> is
replaced by a regular file.</p><h2><code>firewall</code></h2><p>Firewall configuration: default incoming and outgoing policies plus a list of
allow rules. There are two backends, <strong>ufw</strong> (Debian/Ubuntu) and <strong>nftables</strong> </p><p>Allow rules are <strong>additive</strong>. Zap asserts that each declared rule is present and
that the default policies match. A rule added out of band is neither detected
nor removed.</p><!><ul><li><code>backend</code> (required): <code>'ufw'</code> or <code>'nftables'</code>.</li><li><code>allow</code> (required): the allow rules. See <a>Allow rules</a>.</li><li><code>default_incoming</code> (optional): the default incoming policy, <code>'allow'</code> <code>'deny'</code>, or <code>'reject'</code> (default <code>'deny'</code>).</li><li><code>default_outgoing</code> (optional): the default outgoing policy, same values
(default <code>'allow'</code>).</li></ul><h3>Allow rules</h3><p>Each entry in <code>allow</code> <code>'OpenSSH'</code>, which takes no reference and can't begin with <code>-</code>) or a port and
protocol object:</p><ul><li><code>port</code> (required): the port number, 1 to 65535.</li><li><code>proto</code> (optional): <code>'tcp'</code> (default), <code>'udp'</code>, or <code>'any'</code>.</li></ul><h3>Backends</h3><p><strong><code>ufw</code></strong> applies <code>ufw default …</code> policies and a <code>ufw allow</code> <code>ufw --force enable</code>. Named application profiles (<code>'OpenSSH'</code>, <code>'Nginx Full'</code>)
and port rules both work.</p><p><strong><code>nftables</code></strong> installs a single declarative <code>inet filter</code> <code>/etc/nftables.nft</code> (whole, mode <code>600</code>) and loads it with <code>nft -f</code>.</p><ul><li>The ruleset accepts established connections and loopback before the
default-drop policy, so applying it never severs the live SSH session.</li><li>It is scoped to its own table. It does not <code>flush ruleset</code>, so other tables
such as fail2ban's are untouched.</li><li>nftables has <strong>no application profiles</strong>. Use port rules only; a named profile
is a config error.</li><li>Boot persistence is the separate nftables service. Declare a <code>service</code> <code>service: 'nftables'</code>, <code>enabled: true</code>) alongside the firewall,
which loads the same <code>/etc/nftables.nft</code> <strong>required</strong> <code>service: 'nftables'</code> in the same config, because a firewall that silently
vanishes on reboot is a security regression. The <code>alpine_web_firewall</code> recipe
bundles both.</li></ul><p>For both backends, a status probe that <strong>fails</strong> (exits nonzero), or an inactive
ufw, detects as <code>absent</code> <a>detection.md</a>.</p><h2><code>verify</code></h2><p>Assertions checked at detection and again on a wetrun. A <code>verify</code> resource
executes nothing of its own. It checks that conditions hold and, if any
assertion fails, becomes a pending change; on a wetrun its assertions run again at its place in the dependency
order, and one still failing <strong>fails the run there</strong>: changes ordered before it
have already run, and the rest are skipped.
Use it as a guard rail, ordered with <code>depends_on</code> ("this token file must exist
before we proceed"). Like every resource, it is checked
again on every pass.</p><!><ul><li><code>assertions</code> (required): the assertions to check. All must pass.</li></ul><h3>Assertions</h3><p>Each assertion is discriminated on <code>type</code>.</p><p><strong><code>path_exists</code></strong>: assert a path exists, optionally with a required type, mode,
owner, or non-emptiness.</p><ul><li><code>type</code> (required): <code>'path_exists'</code>.</li><li><code>path</code> (required): the absolute path to check, as written: it takes no
reference, and a <code>~</code> or relative path is rejected.</li><li><code>file_type</code> (optional): the required type, <code>'file'</code> or <code>'directory'</code>.</li><li><code>mode</code> (optional): the required octal mode; <code>0644</code> and <code>644</code> are the same.</li><li><code>owner</code> (optional): the required owner, as a user name and not a numeric uid.
A link at <code>path</code> is followed: the type, mode and owner are its target's.</li><li><code>not_empty</code> (optional): whether the path's size must be above zero
(<code>test -s</code>, default false). A directory's size depends on its filesystem, so
this doesn't reliably check that a directory has entries.</li></ul><p><strong><code>command</code></strong>: assert a command exits 0, optionally with a substring in its
stdout.</p><ul><li><code>type</code> (required): <code>'command'</code>.</li><li><code>run</code> (required): the command to run.</li><li><code>expect</code> (optional): a substring that must appear in stdout.</li></ul><h2><code>pipeline</code></h2><p>An ordered, imperative workflow of steps run <strong>sequentially</strong> in declared order.
Reach for it when a procedure really is multi-step and doesn't map onto a single
declarative resource.</p><p>A pipeline has no state to converge to. So it runs on <strong>every</strong> <code>zap status</code> always reads it absent.</p><!><ul><li><code>steps</code> (required): the pipeline steps. See <a>Steps</a>.</li></ul><h3>Steps</h3><ul><li><code>id</code> (required): an id for the step, unique within the pipeline. Two steps
with one id are <strong>rejected by the structural gate</strong>.</li><li><code>run</code> (required): the command this step runs.</li><li><code>name</code> (optional): a display name for the step. A plan lists each step by its <code>id</code>, then its <code>name</code>, above the steps' <code>run</code> commands.</li></ul><p>Steps run in declared order. Concurrent execution and dependencies between steps
aren't supported, so a pipeline-level <code>env</code>, a <code>max_concurrency</code> above 1, or a
step's <code>cwd</code>, <code>env</code>, or <code>depends_on</code> is <strong>rejected by the structural gate</strong> and
not silently ignored; the TypeScript types admit none of them (<code>max_concurrency</code> <code>1</code>). Order steps by position, and inline any per-step environment or working
directory into the step's <code>run</code> (<code>cd … &amp;&amp; FOO=bar cmd</code>).</p><h2><code>build</code></h2><p> <strong>content-addressed and provenance-pinned</strong>: Zap records which exact source
produced the installed artifact, so a moved upstream is detected as drift and
not silently accepted. It is unrelated to <code>deploy.build</code> <code>zap deploy</code> runs before packaging (<a>deploy.md</a>).</p><!><h3>Fields</h3><ul><li><code>source</code> (required): where the source comes from and how its integrity is
verified. See <a><code>source</code></a>.</li><li><code>run</code> (required): the build command, run in the extracted source directory,
such as <code>zig build -p $HOME/.local</code>. It runs as the connecting user,
unprivileged, so an <code>output</code> under a root-owned directory needs the command's
own <code>sudo</code>.</li><li><code>output</code> (required): a path that exists if and only if the build is installed.
It is the detection probe.</li><li><code>cwd</code> (optional): the working directory for <code>run</code>, taken as written (no
reference, no <code>~</code> expansion): an absolute path, or a path relative to the
extracted source directory, which is the default.</li><li><code>env</code> (optional): extra environment for the whole of <code>run</code>, on a remote
target as on a local one. Values resolve references and can hold any byte but U+FDD0, U+FDD1, and
NUL, so <code>env</code> is how a build takes a secret. A name can't begin with <code>__zap_</code>.</li></ul><p>The build toolchain itself (zig, GTK dev packages, and so on) is <strong>not</strong> this
resource's job. Declare it with sibling <code>package</code> or <code>installer</code> resources and
order with <code>depends_on</code>.</p><h3><code>source</code></h3><p>The source is a remote archive:</p><ul><li><code>type</code> (required): <code>'remote'</code>.</li><li><code>url</code> (required): the fetch location (<a>URLs</a> <a>lock.md</a>.</li><li><code>extract</code> (optional): how the archive is unpacked. <code></code> <code></code>. <code>strip_components</code> lives
inside the tar form (beside <code>none</code> it is rejected), and strips leading path
components: <code>1</code> flattens a tarball's single top directory.</li><li><code>auth</code> (optional): a bearer credential for a private byte host, resolved at
the IO boundary and never hashed.</li><li><code>verify</code> <a>Verification</a>.</li><li><code>blake3</code> (optional): a vendored source pin. Present, the source pins itself;
absent, it tracks through <code>zap.lock</code>, where <code>zap update &lt;id></code> advances it; a
tracked source with no lock entry, or with an entry gone stale (the declaration
changed since it was minted), holds the build (<code>undetermined</code> <a>lock.md</a>.</li></ul><h3>Verification</h3><p>When <code>source.verify</code> is set, the fetched archive is verified <strong>before</strong> it is
cached or pinned, so a tampered fetch can never become a build. The supported
scheme is minisign:</p><ul><li><code>scheme</code> (required): <code>'minisign'</code>.</li><li><code>public_key</code> (required): the pinned minisign public key, the 56 base64
characters beginning <code>RW</code> on the key line of a <code>.pub</code> file. Any other shape
fails at config eval.</li><li><code>signature_url</code> (optional): an explicit signature URL, which may carry a
reference. It defaults to the source URL with <code>.minisig</code> appended to its
path, before any query or fragment. The source's <code>auth</code> goes
with the signature request only when the signature URL has the source's
origin (scheme, host, and port); a signature on another origin is fetched
without it.</li></ul><p>Verification shells out to the <code>minisign</code> binary: the one <code>ZAP_MINISIGN</code> names,
an absolute path, else the first in an absolute directory on <code>PATH</code> <code>minisign</code> inside a <code>node_modules</code> directory (an npm script's <code>PATH</code> <code>node_modules/.bin</code>, which any installed package can fill), and one where the
binary, or any directory from where it resolves up to <code>/</code> (and the same for the
directory it was found in and for each link on the way), is writable by a group
or others, or owned by an account other than root and you. Once those
directories are trusted, only root or you could swap the binary between the
check and the run. A refusal or a failed verification names the binary's path. Zap adds no crypto dependency of
its own and uses the upstream's trust mechanism.</p><p>A good signature says the key's holder signed these bytes, not that they are
the version the URL names: any archive the same key signed verifies, an older
release included. The pin is what fixes the version, and a tracked pin is
minted from whatever verified archive the URL served at that fetch, so read the
pin change in the lock diff as you would a version bump.</p><p>It runs once, at the fetch on a cache miss. A cache hit hashes the bytes against
the pin again. Bytes that hash to the pin are the pinned bytes, however they
reached the cache: a tracked pin is only ever minted from a verified fetch, and
a vendored pin is your own statement of exactly which bytes to trust.</p><h3>Detection</h3><p>After a successful build Zap writes a provenance sidecar, <code>&lt;output>.zap-build</code>:
a blake3 over the source pin and the build's <code>extract</code>, <code>run</code>, <code>cwd</code>, and <code>env</code> <a>detection.md</a>).</p><h2>See also</h2><ul><li><a>concepts.md</a>: the model and the verdicts.</li><li><a>configs.md</a>: writing a config; ordering, triggers, the gates.</li><li><a>detection.md</a>: how each resource type's current state is
read.</li><li><a>lock.md</a>: pins, <code>zap.lock</code>, and the sentinel and sidecar files.</li><li><a>env.md</a>: references, the env file, secrets.</li><li><a>deploy.md</a>: the <code>zap deploy</code> release mechanism.</li><li><a>recipes.md</a>: the shipped config fragments.</li></ul>`,1);function m(a,m){l(m,!0);let oe=ie(`resources`);s(`zhuu8u`,e=>{t(()=>{ee.title=`Resources — zap`})}),d(a,{get tome(){return oe},children:(t,ee)=>{p(t,{children:(t,ee)=>{var a=ae(),s=e(ne(a));f(s,{lang:`ts`,dangerous_raw_html:`<span class="token_special_keyword">export</span> <span class="token_special_keyword">default</span> <span class="token_punctuation">(</span>zap<span class="token_punctuation">)</span> <span class="token_operator">=></span> <span class="token_punctuation">{</span>
	zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>local<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>apt<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">}});</span>
	zap<span class="token_punctuation">.</span><span class="token_function">build</span><span class="token_punctuation">({</span>
		id<span class="token_operator">:</span> <span class="token_string">'ghostty'</span><span class="token_punctuation">,</span>
		source<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'remote'</span><span class="token_punctuation">,</span> url<span class="token_operator">:</span> <span class="token_string">'https://example.com/ghostty.tar.gz'</span><span class="token_punctuation">,</span> extract<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'tar.gz'</span><span class="token_punctuation">,</span> strip_components<span class="token_operator">:</span> <span class="token_number">1</span><span class="token_punctuation">}},</span>
		run<span class="token_operator">:</span> <span class="token_string">'zig build -p $HOME/.local -Doptimize=ReleaseFast'</span><span class="token_punctuation">,</span>
		output<span class="token_operator">:</span> <span class="token_string">'$HOME/.local/bin/ghostty'</span><span class="token_punctuation">,</span>
	<span class="token_punctuation">});</span>
<span class="token_punctuation">};</span>`});var c=e(s);o(c,`id`,`resource-types`);var l=e(c,2),ie=e(n(l),5);r(),i(l);var d=e(l);o(d,`id`,`one-resource-per-thing`);var p=e(d,3),m=e(n(p),16);m.nodeValue=` are dropped and
`;var oe=e(m,6);oe.nodeValue=` and
`,r(8),i(p);var se=e(p);o(se,`id`,`urls`);var ce=e(se),le=e(n(ce),4);le.nodeValue=`
(a credential goes in `;var ue=e(le,10);ue.nodeValue=` source's and its signature's, an
`,r(18),i(ce);var de=e(ce);o(de,`id`,`account-names`);var fe=e(de),pe=e(n(fe),7);pe.nodeValue=` field take an account
`,r(6),i(fe);var me=e(fe),he=e(n(me),8);he.nodeValue=`. That is the
`;var ge=e(he,10);ge.nodeValue=`
paths, where a stray character would break out of the form.`,i(me);var _e=e(me);o(_e,`id`,`package`);var h=e(_e),ve=e(n(h),2);ve.nodeValue=`
(Debian/Ubuntu) or `,r(12),i(h);var ye=e(h);f(ye,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">pkg</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">,</span> <span class="token_special_keyword">from</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>apt<span class="token_operator">:</span> <span class="token_string">'ripgrep'</span><span class="token_punctuation">}});</span>`});var g=e(ye),_=n(g),be=e(n(_));be.nodeValue=` (required): a map from package manager to package name, such as
`;var xe=e(be);xe.textContent=`{apt: 'ripgrep'}`;var Se=e(xe,4);o(Se,`href`,`#package-names`),r(),i(_);var Ce=e(_),we=e(n(Ce));we.nodeValue=` (optional): a custom check, either a path (tested for existence) or a
command (exit 0). It defaults to the manager's own query. A check beginning
`,r(12),i(Ce),i(g);var Te=e(g,2);o(Te,`id`,`package-names`);var v=e(Te,4),Ee=n(v),De=e(n(Ee),6);De.nodeValue=` and
`,r(8),i(Ee),r(),i(v);var y=e(v),Oe=e(n(y),8);Oe.nodeValue=`
installs it but never reads installed, so write the name without it.`,i(y);var ke=e(y);o(ke,`id`,`apt_repo`);var Ae=e(ke,2);f(Ae,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">apt_repo</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'pgdg'</span><span class="token_punctuation">,</span>
	key_url<span class="token_operator">:</span> <span class="token_string">'https://www.postgresql.org/media/keys/ACCC4CF8.asc'</span><span class="token_punctuation">,</span>
	source<span class="token_operator">:</span> <span class="token_string">'deb https://apt.postgresql.org/pub/repos/apt bookworm-pgdg main'</span><span class="token_punctuation">,</span>
<span class="token_punctuation">});</span>`});var b=e(Ae),x=n(b),je=e(n(x),2);o(je,`href`,`#urls`),r(),i(x);var S=e(x),Me=e(n(S),3);Me.nodeValue=`
(`;var Ne=e(Me);r(),i(S);var C=e(S,2),Pe=e(n(C));Pe.nodeValue=` (optional): where the key is stored. It defaults to
`,r(2),i(C);var Fe=e(C),Ie=e(n(Fe),3);Ie.nodeValue=` file path. It defaults to
`,r(4),i(Fe),i(b);var w=e(b,2),Le=e(n(w),3);Le.nodeValue=` sourced, so it can
reference the distro's variables for portability. For example,
`;var Re=e(Le,8);Re.nodeValue=` is written into that line, so the shell reads it too.
`;var ze=e(Re,6);ze.nodeValue=` the same
way, so a templated line still converges. Because the shell reads the line,
`,r(2),i(w);var Be=e(w,2);f(Be,{lang:null,content:`content hash mismatch for https://www.postgresql.org/media/keys/ACCC4CF8.asc: declared <pin>, fetched <blake3 of what was served>`});var T=e(Be),Ve=e(n(T),8);Ve.nodeValue=` mints its pin, and a wetrun records it in
`,r(4),i(T);var He=e(T);o(He,`id`,`script`);var Ue=e(He,2);f(Ue,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">script</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'enable-lingering'</span><span class="token_punctuation">,</span>
	check<span class="token_operator">:</span> <span class="token_string">'loginctl show-user $USER | grep -q Linger=yes'</span><span class="token_punctuation">,</span>
	run<span class="token_operator">:</span> <span class="token_string">'sudo loginctl enable-linger $USER'</span><span class="token_punctuation">,</span>
<span class="token_punctuation">});</span>`});var E=e(Ue),We=e(n(E),3),Ge=e(n(We),9);Ge.nodeValue=` in it, or a secret. A name can't begin with
`,r(2),i(We),i(E);var Ke=e(E,3);f(Ke,{lang:null,content:`  [+] migrate  (script)
      cwd: /srv/app
      env: DATABASE_URL={env:DATABASE_URL}
      env: MODE=prod
      check: test -f .migrated
      > ./migrate.sh`});var D=e(Ke),qe=e(n(D),8);qe.nodeValue=`
that can't enter it fails the change with nothing run. A `,r(4),i(D);var Je=e(D);o(Je,`id`,`installer`);var Ye=e(Je,2);f(Ye,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">installer</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'deno'</span><span class="token_punctuation">,</span>
	url<span class="token_operator">:</span> <span class="token_string">'https://deno.land/install.sh'</span><span class="token_punctuation">,</span>
	check<span class="token_operator">:</span> <span class="token_string">'~/.deno/bin/deno'</span><span class="token_punctuation">,</span>
<span class="token_punctuation">});</span>`});var O=e(Ye),k=n(O),Xe=e(n(k),4);o(Xe,`href`,`#urls`),r(3),i(k);var Ze=e(k,2),Qe=e(n(Ze),3);Qe.nodeValue=`). It is
one line, shown in the step as written and read by the target's shell like a
`,r(6),i(Ze),i(O);var A=e(O),$e=e(n(A),4);$e.nodeValue=` with
`,r(2),i(A);var et=e(A);o(et,`id`,`user`);var j=e(et),tt=n(j);tt.nodeValue=`A Unix user account. Zap creates the account if it doesn't exist, with
`,r(4),i(j);var M=e(j),nt=e(n(M),4);nt.nodeValue=` and
`,r(2),i(M);var N=e(M),P=e(n(N)),rt=e(n(P),8);rt.nodeValue=` or
`;var it=e(rt,3);f(it,{lang:null,content:"deploy's home in /etc/passwd is /srv/deploy, not /home/deploy: zap manages a user's home as /home/<name>, so its `home_mode` and `ssh_keys` would miss the account's own"}),r(),i(P);var at=e(P),F=e(n(at),5),ot=n(F),st=e(n(ot),2);st.nodeValue=`:
`,r(4),i(ot),r(4),i(F);var ct=e(F);f(ct,{lang:null,content:`/home/deploy is owned by uid 1002 (deploy's uid is 1001); chown it to deploy, or remove it: zap manages a user's home as the directory /home/deploy, the user's own or root's`}),r(),i(at),i(N);var lt=e(N);f(lt,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">user</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'deploy'</span><span class="token_punctuation">,</span>
	username<span class="token_operator">:</span> <span class="token_string">'deploy'</span><span class="token_punctuation">,</span>
	shell<span class="token_operator">:</span> <span class="token_string">'/bin/bash'</span><span class="token_punctuation">,</span>
	ssh_keys<span class="token_operator">:</span> <span class="token_punctuation">{</span>copy_from<span class="token_operator">:</span> <span class="token_string">'root'</span><span class="token_punctuation">},</span>
	sudo<span class="token_operator">:</span> <span class="token_string">'nopasswd'</span><span class="token_punctuation">,</span>
<span class="token_punctuation">});</span>`});var I=e(lt),L=n(I),ut=e(n(L),2);o(ut,`href`,`#account-names`);var dt=e(ut);dt.nodeValue=`.
`,r(2),i(L);var R=e(L,3),ft=e(n(R),3);ft.nodeValue=`, as either
`;var pt=e(ft);pt.textContent=`{copy_from: '<user>'}`;var mt=e(pt,2);mt.textContent=`{keys: ['ssh-ed25519 …', …]}`;var ht=e(mt,4);o(ht,`href`,`#ssh-keys`),r(),i(R);var z=e(R),gt=e(n(z),2);o(gt,`href`,`#sudo`),r(),i(z);var _t=e(z),vt=e(n(_t));vt.nodeValue=` (optional): supplementary groups the user must belong to, such as
`,r(6),i(_t),i(I);var yt=e(I);o(yt,`id`,`ssh-keys`);var B=e(yt,5),bt=e(n(B),4);bt.nodeValue=` password field to
`,r(6),i(B);var xt=e(B,2);o(xt,`id`,`sudo`);var V=e(xt),St=e(n(V)),Ct=n(St);Ct.textContent=`{mode: 'nopasswd' | 'password', commands: ['<sudoers spec>', …]}`,r(3),i(St),r(2),i(V);var wt=e(V,2);o(wt,`id`,`directory`);var Tt=e(wt,2);f(Tt,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">directory</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'app-dir'</span><span class="token_punctuation">,</span> path<span class="token_operator">:</span> <span class="token_string">'/opt/app'</span><span class="token_punctuation">,</span> mode<span class="token_operator">:</span> <span class="token_string">'755'</span><span class="token_punctuation">});</span>`});var H=e(Tt,2),Et=e(n(H),6);Et.nodeValue=`,
`,r(4),i(H);var U=e(H),Dt=e(n(U),3);o(Dt,`href`,`#link`),r(),i(U);var Ot=e(U);o(Ot,`id`,`file`);var W=e(Ot),kt=e(n(W),8);kt.nodeValue=`, or
`,r(2),i(W);var G=e(W),At=n(G);At.nodeValue=`The file's parent directory is created automatically if missing, like
`;var jt=e(At,2);jt.nodeValue=`: each directory made takes the owner and group of the nearest one
that was already there (the writer's, below a directory anyone may write, as in
`;var Mt=e(jt);o(Mt,`href`,`#directory`),r(5),i(G);var K=e(G),Nt=e(n(K),9);o(Nt,`href`,`#link`),r(),i(K);var q=e(K,2),Pt=n(q);Pt.nodeValue=`A mode is never kept from a file with an extended POSIX access list (ACL): its
mode bits show the list's mask rather than its group's, and the rewrite carries
no list, so a kept mode would hand the group what the list gave one account. A
`,r(18),i(q);var J=e(q),Ft=e(n(J),9);r(),i(J);var It=e(J);f(It,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'motd'</span><span class="token_punctuation">,</span>
	path<span class="token_operator">:</span> <span class="token_string">'/etc/motd'</span><span class="token_punctuation">,</span>
	content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'inline'</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> <span class="token_string">'Managed by zap.\\n'</span><span class="token_punctuation">},</span>
	mode<span class="token_operator">:</span> <span class="token_string">'644'</span><span class="token_punctuation">,</span>
<span class="token_punctuation">});</span>`});var Y=e(It),X=e(n(Y)),Lt=e(n(X),2);o(Lt,`href`,`#content`),r(),i(X);var Z=e(X,2),Rt=e(n(Z));Rt.nodeValue=` (optional): the owner, as a user name and not a numeric uid. See
`;var zt=e(Rt);o(zt,`href`,`#account-names`),r(),i(Z);var Q=e(Z,2),Bt=e(n(Q),4);o(Bt,`href`,`#service`),r(),i(Q);var Vt=e(Q),Ht=e(n(Vt));Ht.nodeValue=` (optional): a command that must exit 0 after the write, such as
`;var Ut=e(Ht,6);Ut.nodeValue=`). See
`;var Wt=e(Ut);o(Wt,`href`,`#validated-writes`),r(),i(Vt),i(Y);var Gt=e(Y);o(Gt,`id`,`validated-writes`);var Kt=e(Gt,2),qt=n(Kt);qt.nodeValue=`Checking in place is what lets it cover a file some larger config includes:
`,r(2),i(Kt);var Jt=e(Kt);f(Jt,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'nginx-config'</span><span class="token_punctuation">,</span>
	path<span class="token_operator">:</span> <span class="token_string">'/etc/nginx/sites-available/example.com'</span><span class="token_punctuation">,</span>
	content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'inline'</span><span class="token_punctuation">,</span> content<span class="token_operator">:</span> site<span class="token_punctuation">},</span>
	validate<span class="token_operator">:</span> <span class="token_constant">NGINX_VALIDATE</span><span class="token_punctuation">,</span>
<span class="token_punctuation">});</span>`});var Yt=e(Jt,3),Xt=e(n(Yt));o(Xt,`href`,`#verify`);var Zt=e(Xt);Zt.nodeValue=`
running the same command closes. It is checked again on every plan. A config the
running service couldn't reload onto then shows up as a pending change and does
not read as converged, and `,r(2),i(Yt);var Qt=e(Yt);f(Qt,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">verify</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'nginx-config-valid'</span><span class="token_punctuation">,</span>
	<span class="token_operator">...</span><span class="token_function">nginx_config_verify</span><span class="token_punctuation">(),</span> <span class="token_comment">// {assertions: [{type: 'command', run: NGINX_VALIDATE}]}</span>
	depends_on<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'nginx-service'</span><span class="token_punctuation">],</span>
<span class="token_punctuation">});</span>`});var $t=e(Qt,2);o($t,`id`,`content`);var en=e($t,4),tn=e(n(en),2);tn.textContent=`{{key}}`,r(),i(en);var nn=e(en),rn=e(n(nn)),an=e(n(rn),2);an.textContent=`{{key}}`;var on=e(an,2);on.textContent=`{{ .Values.port }}`,r(),i(rn);var sn=e(rn),cn=e(n(sn),2);cn.textContent=`{{key}}`;var ln=e(cn);ln.nodeValue=`, after a
reference in a string value resolves. A value that isn't a string is
substituted as its compact JSON text and takes no reference at any depth; pass
the value as a string var of its own. A reference can't stand for the whole
`,r(6),i(sn),r(),i(nn);var un=e(nn),dn=e(n(un));dn.textContent=`{{name}}`;var fn=e(dn,4);fn.textContent=`{{…}}`;var pn=e(fn,2);pn.textContent=`{{name}}`,r(),i(un);var mn=e(un,2),hn=e(n(mn),3);hn.textContent=`}`;var gn=e(hn);gn.nodeValue=`
in an nginx `;var _n=e(gn);_n.textContent=`server_name {{domain}}`,r(),i(mn);var vn=e(mn,2);f(vn,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'nginx-site'</span><span class="token_punctuation">,</span>
	path<span class="token_operator">:</span> <span class="token_string">'/etc/nginx/sites-available/app'</span><span class="token_punctuation">,</span>
	content<span class="token_operator">:</span> <span class="token_punctuation">{</span>
		type<span class="token_operator">:</span> <span class="token_string">'template'</span><span class="token_punctuation">,</span>
		template<span class="token_operator">:</span> site<span class="token_punctuation">,</span>
		vars<span class="token_operator">:</span> <span class="token_punctuation">{</span>domain<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'DEPLOY_DOMAIN'</span><span class="token_punctuation">),</span> port<span class="token_operator">:</span> <span class="token_number">4040</span><span class="token_punctuation">},</span>
		kinds<span class="token_operator">:</span> <span class="token_punctuation">{</span>domain<span class="token_operator">:</span> <span class="token_string">'hostname'</span><span class="token_punctuation">,</span> port<span class="token_operator">:</span> <span class="token_string">'port'</span><span class="token_punctuation">},</span>
	<span class="token_punctuation">},</span>
<span class="token_punctuation">});</span>`});var yn=e(vn),bn=e(n(yn));r(),i(yn);var xn=e(yn,4),Sn=e(n(xn),2);o(Sn,`href`,`#build`),r(),i(xn);var Cn=e(xn),wn=e(n(Cn)),Tn=e(n(wn),2);o(Tn,`href`,`#urls`);var En=e(Tn);En.nodeValue=`). It may carry a
reference, resolved when Zap fetches; how the lock addresses it is in
`;var Dn=e(En);r(),i(wn);var On=e(wn),kn=e(n(On),2);kn.textContent=`{type: 'none'}`;var An=e(kn,2);An.textContent=`{type: 'tar.xz' | 'tar.gz', strip_components?: N}`,r(7),i(On);var jn=e(On),Mn=e(n(jn),2);o(Mn,`href`,`#remote-auth`),r(),i(jn);var Nn=e(jn),Pn=e(n(Nn),3);Pn.nodeValue=`. See
`;var Fn=e(Pn);r(),i(Nn),i(Cn);var In=e(Cn),Ln=e(n(In),3);Ln.nodeValue=` sentinel;
detection never fetches. See
`;var Rn=e(Ln);r(),i(In);var zn=e(In),Bn=e(n(zn));Bn.nodeValue=` Placement and extraction escalate as needed: a
`;var Vn=e(Bn,2);Vn.nodeValue=` placement or an archive extract into a root-owned destination (such as
`;var Hn=e(Vn,15);o(Hn,`href`,`#file`),r(15),i(zn);var Un=e(zn),Wn=e(n(Un),6);Wn.nodeValue=` directory of the extracting user's
(root's, when it escalated) beside the destination; killed between the two
renames, it holds the old tree. One is also left, empty, where an account that
can write the parent renamed it. The staging name is 12 bytes longer than the
destination's, so a destination name within 12 bytes of the filesystem's
`,r(2),i(Un);var Gn=e(Un);o(Gn,`id`,`remote-auth`);var Kn=e(Gn,2);f(Kn,{lang:`ts`,dangerous_raw_html:`auth<span class="token_operator">:</span> <span class="token_punctuation">{</span>scheme<span class="token_operator">:</span> <span class="token_string">'bearer'</span><span class="token_punctuation">,</span> token<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'API_TOKEN'</span><span class="token_punctuation">)}</span>`});var qn=e(Kn);o(qn,`id`,`link`);var Jn=e(qn,2);f(Jn,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">link</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'vim'</span><span class="token_punctuation">,</span> path<span class="token_operator">:</span> <span class="token_string">'~/.local/bin/vim'</span><span class="token_punctuation">,</span> target<span class="token_operator">:</span> <span class="token_string">'/usr/bin/nvim'</span><span class="token_punctuation">});</span>`});var Yn=e(Jn,3);o(Yn,`id`,`service`);var Xn=e(Yn),Zn=e(n(Xn),2);Zn.nodeValue=` or
`;var Qn=e(Zn,3);o(Qn,`href`,`#file`);var $n=e(Qn);$n.nodeValue=`'s
`,r(2),i(Xn);var er=e(Xn);f(er,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">service</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'nginx'</span><span class="token_punctuation">,</span> service<span class="token_operator">:</span> <span class="token_string">'nginx'</span><span class="token_punctuation">,</span> running<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">,</span> reload_on<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'nginx-conf'</span><span class="token_punctuation">]});</span>`});var tr=e(er),nr=e(n(tr),2),rr=e(n(nr));rr.nodeValue=` (optional): whether it should be running now. Omit it to leave
runtime state unmanaged. On OpenRC, starting a crashed service (its daemon
died while it was marked started) first resets it with
`,r(2),i(nr);var ir=e(nr),ar=e(n(ir),3);ar.nodeValue=` on systemd,
`,r(2),i(ir);var or=e(ir),sr=e(n(or),3);sr.nodeValue=` on systemd and
`,r(2),i(or),i(tr);var cr=e(tr),lr=n(cr);lr.nodeValue=`A trigger acts only on a running service. A service that isn't running is left
as it is, and starts on the new state when something starts it, so a unit file
written on a first deploy restarts nothing before its binary is there. A service
converged but for its trigger runs the trigger alone (after systemd's
`;var ur=e(lr,8);ur.nodeValue=`, or a file's
`,r(2),i(cr);var dr=e(cr,3),fr=e(n(dr),2);fr.nodeValue=`) parses. Its services detect as
`,r(8),i(dr);var pr=e(dr);o(pr,`id`,`pending-triggers`);var mr=e(pr,3);f(mr,{lang:null,content:`  [~] nginx-service  (service)
      (pending reload from an earlier apply)
      > sudo systemctl daemon-reload
      > sudo systemctl try-reload-or-restart nginx`});var hr=e(mr,2),gr=e(n(hr),8);gr.nodeValue=`
component, a `;var _r=e(gr,10);_r.nodeValue=`, so no path below the link leads there), a
`;var vr=e(_r,8);vr.nodeValue=`,
`,r(8),i(hr);var yr=e(hr,3);o(yr,`id`,`database`);var br=e(yr,2);f(br,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">database</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'app-db'</span><span class="token_punctuation">,</span> engine<span class="token_operator">:</span> <span class="token_string">'postgresql'</span><span class="token_punctuation">,</span> database_name<span class="token_operator">:</span> <span class="token_string">'app'</span><span class="token_punctuation">,</span> username<span class="token_operator">:</span> <span class="token_string">'app'</span><span class="token_punctuation">});</span>`});var xr=e(br),Sr=e(n(xr),3),Cr=e(n(Sr),3);Cr.nodeValue=` rules. See
`;var wr=e(Cr);o(wr,`href`,`#database-auth`),r(),i(Sr),i(xr);var Tr=e(xr),Er=e(n(Tr),20);Er.nodeValue=`
reads as a keyword in that column (`;var Dr=e(Er,8);Dr.nodeValue=`,
`,r(4),i(Tr);var Or=e(Tr),kr=n(Or);kr.nodeValue=`Both identifiers are taken literally and never shell-expanded. They accept
references, resolved on the operator's machine. A dev config that
wants "the role matching the OS user" on every machine declares
`,r(4),i(Or);var Ar=e(Or);o(Ar,`id`,`database-auth`);var jr=e(Ar),Mr=e(n(jr)),Nr=e(n(Mr),3);Nr.nodeValue=` auth method of those rules (default
`;var Pr=e(Nr,12);Pr.nodeValue=`
already takes; `;var Fr=e(Pr,6);Fr.nodeValue=` and
`,r(6),i(Mr),i(jr);var Ir=e(jr,2),Lr=e(n(Ir),8);Lr.nodeValue=`, say)
reads present, though the earlier line decides those connections, and a
`;var Rr=e(Lr,6);Rr.nodeValue=` account, which must own
the file and be able to write its directory, as a stock install has it; a
`;var zr=e(Rr,8);zr.nodeValue=`
(PostgreSQL 10 or later; on an older server the step fails), which parses the
file on disk, and fails without reloading if any line of it has an `;var Br=e(zr,2);Br.nodeValue=`. The
reload is only a signal, so after it the step waits, up to 30 seconds, for
`;var Vr=e(Br,2);Vr.nodeValue=` to move, read from a new connection each second; once it
moves, every new connection, a dependent's included, sees the rule. A
`;var Hr=e(Vr,10);Hr.nodeValue=`
line still orders ahead of Zap's rule.`,i(Ir);var Ur=e(Ir);o(Ur,`id`,`swap`);var Wr=e(Ur,2);f(Wr,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">swap</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'swap'</span><span class="token_punctuation">,</span> size<span class="token_operator">:</span> <span class="token_string">'2G'</span><span class="token_punctuation">});</span>`});var Gr=e(Wr),Kr=e(n(Gr)),qr=e(n(Kr),5);qr.nodeValue=` line. It is not
`,r(2),i(Kr),i(Gr);var Jr=e(Gr,3),Yr=e(n(Jr),5);o(Yr,`href`,`#file`),r(5),i(Jr);var Xr=e(Jr);o(Xr,`id`,`firewall`);var Zr=e(Xr),Qr=e(n(Zr),4);Qr.nodeValue=`
(the native backend on Alpine).`,i(Zr);var $r=e(Zr,2);f($r,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">firewall</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'fw'</span><span class="token_punctuation">,</span>
	backend<span class="token_operator">:</span> <span class="token_string">'ufw'</span><span class="token_punctuation">,</span>
	allow<span class="token_operator">:</span> <span class="token_punctuation">[</span><span class="token_string">'OpenSSH'</span><span class="token_punctuation">,</span> <span class="token_punctuation">{</span>port<span class="token_operator">:</span> <span class="token_number">443</span><span class="token_punctuation">,</span> proto<span class="token_operator">:</span> <span class="token_string">'tcp'</span><span class="token_punctuation">}],</span>
<span class="token_punctuation">});</span>`});var ei=e($r),ti=e(n(ei)),ni=e(n(ti),2);o(ni,`href`,`#allow-rules`),r(),i(ti);var ri=e(ti),ii=e(n(ri),3);ii.nodeValue=`,
`,r(6),i(ri),r(),i(ei);var ai=e(ei);o(ai,`id`,`allow-rules`);var oi=e(ai),si=e(n(oi),2);si.nodeValue=` is either a named ufw profile (a string, such as
`,r(4),i(oi);var ci=e(oi,2);o(ci,`id`,`backends`);var li=e(ci),ui=e(n(li),5);ui.nodeValue=` per rule, then
`,r(6),i(li);var di=e(li),fi=e(n(di),3);fi.nodeValue=` ruleset at
`,r(6),i(di);var pi=e(di),mi=e(n(pi),3),hi=e(n(mi),2);hi.nodeValue=`
resource (`;var gi=e(hi,6);gi.nodeValue=` at boot. This companion service is
`;var _i=e(gi,2);_i.nodeValue=`: the structural gate rejects an nftables firewall with no enabled
`,r(4),i(mi),i(pi);var vi=e(pi),yi=e(n(vi),4);yi.nodeValue=` (needs setting up) rather than holding; a probe that
times out, or whose batch fails, still holds. This is the fresh-host case, where the probe runs before
the same config installs ufw or nftables. See
`;var bi=e(yi);r(),i(vi);var xi=e(vi);o(xi,`id`,`verify`);var Si=e(xi,2);f(Si,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">verify</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'token-present'</span><span class="token_punctuation">,</span>
	assertions<span class="token_operator">:</span> <span class="token_punctuation">[{</span>type<span class="token_operator">:</span> <span class="token_string">'path_exists'</span><span class="token_punctuation">,</span> path<span class="token_operator">:</span> <span class="token_string">'/home/deploy/.zap/api_token'</span><span class="token_punctuation">,</span> file_type<span class="token_operator">:</span> <span class="token_string">'file'</span><span class="token_punctuation">,</span> not_empty<span class="token_operator">:</span> <span class="token_boolean">true</span><span class="token_punctuation">}],</span>
<span class="token_punctuation">});</span>`});var Ci=e(Si,2);o(Ci,`id`,`assertions`);var wi=e(Ci,6);o(wi,`id`,`pipeline`);var Ti=e(wi,2),Ei=e(n(Ti),2);Ei.nodeValue=` wetrun, a dry
run of a config that declares one always has a pending change (exit 2), and
`,r(2),i(Ti);var Di=e(Ti);f(Di,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">pipeline</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'migrate'</span><span class="token_punctuation">,</span>
	steps<span class="token_operator">:</span> <span class="token_punctuation">[</span>
		<span class="token_punctuation">{</span>id<span class="token_operator">:</span> <span class="token_string">'backup'</span><span class="token_punctuation">,</span> run<span class="token_operator">:</span> <span class="token_string">'pg_dump app > /tmp/app.sql'</span><span class="token_punctuation">},</span>
		<span class="token_punctuation">{</span>id<span class="token_operator">:</span> <span class="token_string">'apply'</span><span class="token_punctuation">,</span> run<span class="token_operator">:</span> <span class="token_string">'./migrate.sh'</span><span class="token_punctuation">},</span>
	<span class="token_punctuation">],</span>
<span class="token_punctuation">});</span>`});var Oi=e(Di),ki=n(Oi),Ai=e(n(ki),2);o(Ai,`href`,`#steps`),r(),i(ki),i(Oi);var ji=e(Oi);o(ji,`id`,`steps`);var $=e(ji,2),Mi=e(n($),14);Mi.nodeValue=`
only as `,r(6),i($);var Ni=e($);o(Ni,`id`,`build`);var Pi=e(Ni),Fi=n(Pi);Fi.nodeValue=`Builds a tool from a fetched source archive and installs it, for upstreams that
ship source and no prebuilt binary (zig, ghostty). The source is
`;var Ii=e(Fi,4);Ii.nodeValue=`, the local command
`;var Li=e(Ii,3);r(),i(Pi);var Ri=e(Pi);f(Ri,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">build</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'ghostty'</span><span class="token_punctuation">,</span>
	source<span class="token_operator">:</span> <span class="token_punctuation">{</span>
		type<span class="token_operator">:</span> <span class="token_string">'remote'</span><span class="token_punctuation">,</span>
		url<span class="token_operator">:</span> <span class="token_string">'https://release.files.ghostty.org/1.3.1/ghostty-1.3.1.tar.gz'</span><span class="token_punctuation">,</span>
		extract<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'tar.gz'</span><span class="token_punctuation">,</span> strip_components<span class="token_operator">:</span> <span class="token_number">1</span><span class="token_punctuation">},</span>
		verify<span class="token_operator">:</span> <span class="token_punctuation">{</span>
			scheme<span class="token_operator">:</span> <span class="token_string">'minisign'</span><span class="token_punctuation">,</span>
			public_key<span class="token_operator">:</span> <span class="token_string">'RWQlAjJC23149WL2sEpT/l0QKy7hMIFhYdQOFy0Z7z7PbneUgvlsnYcV'</span><span class="token_punctuation">,</span>
		<span class="token_punctuation">},</span>
		<span class="token_comment">// blake3: '…',  // vendored pin (see below); omit to track via zap.lock</span>
	<span class="token_punctuation">},</span>
	run<span class="token_operator">:</span> <span class="token_string">'zig build -p $HOME/.local -Doptimize=ReleaseFast'</span><span class="token_punctuation">,</span>
	output<span class="token_operator">:</span> <span class="token_string">'$HOME/.local/bin/ghostty'</span><span class="token_punctuation">,</span>
<span class="token_punctuation">});</span>`});var zi=e(Ri);o(zi,`id`,`fields`);var Bi=e(zi),Vi=n(Bi),Hi=e(n(Vi),2);o(Hi,`href`,`#source`),r(),i(Vi),r(4),i(Bi);var Ui=e(Bi,2);o(Ui,`id`,`source`);var Wi=e(Ui,2),Gi=e(n(Wi)),Ki=e(n(Gi),2);o(Ki,`href`,`#urls`);var qi=e(Ki);qi.nodeValue=`). It may carry a
reference, resolved when Zap fetches; how the lock addresses it is in
`;var Ji=e(qi);r(),i(Gi);var Yi=e(Gi),Xi=e(n(Yi),2);Xi.textContent=`{type: 'none'}`;var Zi=e(Xi);Zi.nodeValue=` is the
default; the other form is
`;var Qi=e(Zi);Qi.textContent=`{type: 'tar.xz' | 'tar.gz', strip_components?: N}`,r(7),i(Yi);var $i=e(Yi,2),ea=e(n($i));ea.nodeValue=` (optional): upstream-signature verification. See
`;var ta=e(ea);o(ta,`href`,`#verification`),r(),i($i);var na=e($i),ra=e(n(na),7);ra.nodeValue=`, exit 1) in the read-only commands. See
`;var ia=e(ra);r(),i(na),i(Wi);var aa=e(Wi);o(aa,`id`,`verification`);var oa=e(aa,3),sa=e(n(oa),6);sa.nodeValue=`. Its exit
status is the verdict that lets the bytes be cached and pinned, so Zap refuses a
`;var ca=e(sa,6);ca.nodeValue=` leads with
`,r(4),i(oa);var la=e(oa,3);o(la,`id`,`detection`);var ua=e(la),da=e(n(ua),10);da.nodeValue=`
as declared. Detection compares it with the desired provenance, so a moved
upstream or a changed build rebuilds
(`;var fa=e(da);r(),i(ua);var pa=e(ua);o(pa,`id`,`see-also`);var ma=e(pa),ha=n(ma),ga=n(ha);r(),i(ha);var _a=e(ha),va=n(_a);r(),i(_a);var ya=e(_a),ba=n(ya);r(),i(ya);var xa=e(ya),Sa=n(xa);r(3),i(xa);var Ca=e(xa),wa=n(Ca);r(),i(Ca);var Ta=e(Ca),Ea=n(Ta);r(3),i(Ta);var Da=e(Ta),Oa=n(Da);r(),i(Da),i(ma),te((e,t,ee,te,n,ne,r,i,a,re,s,c,l,u,d,f,p,ae,m)=>{o(ie,`href`,e),o(Ne,`href`,t),o(Ft,`href`,ee),o(bn,`href`,te),o(Dn,`href`,n),o(Fn,`href`,ne),o(Rn,`href`,r),o(bi,`href`,i),o(Li,`href`,a),o(Ji,`href`,re),o(ia,`href`,s),o(fa,`href`,c),o(ga,`href`,l),o(va,`href`,u),o(ba,`href`,d),o(Sa,`href`,f),o(wa,`href`,p),o(Ea,`href`,ae),o(Oa,`href`,m)},[()=>u(`docs/env#target-categorized-resolution`),()=>u(`docs/lock#two-kinds-of-fetched-content`),()=>u(`docs/security#writes-on-the-host`),()=>u(`docs/recipes`),()=>u(`docs/lock#what-an-entry-holds`),()=>u(`docs/lock#two-kinds-of-fetched-content`),()=>u(`docs/detection#content-is-compared-by-digest`),()=>u(`docs/detection#kinds-that-read-a-failed-probe-as-absent`),()=>u(`docs/deploy#configuration`),()=>u(`docs/lock#what-an-entry-holds`),()=>u(`docs/lock#two-kinds-of-fetched-content`),()=>u(`docs/detection#build-exact-provenance-not-a-version-string`),()=>u(`docs/concepts`),()=>u(`docs/configs`),()=>u(`docs/detection`),()=>u(`docs/lock`),()=>u(`docs/env`),()=>u(`docs/deploy`),()=>u(`docs/recipes`)]),re(t,a)},$$slots:{default:!0}})},$$slots:{default:!0}}),c()}export{m as t};