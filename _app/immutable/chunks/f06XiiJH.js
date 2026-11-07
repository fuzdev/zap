import{$ as e,G as t,J as n,K as r,X as i,Z as a,dt as o,ft as s,j as c,k as l,l as u,m as d,ot as f,st as p}from"./CkSeWg2M.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as g}from"./k6TRNp0w.js";import{t as _}from"./DH_LefOd.js";import{t as v}from"./BzaAmULn.js";var y=c(`<p>How Zap pins the evaluator that runs the config and the content it fetches,
what <code>zap.lock</code> holds, the commands that move it, and what Zap keeps under <code>~/.zap</code>. Background: <a>concepts.md</a>.</p><p><code>zap.lock</code> is <strong>declared intent</strong>, not cached state. It belongs in version
control with the config. It records the toolchain pin and the tracked pins;
everything else Zap knows about a machine it reads live. The file is the
config's name with <code>.lock</code> for its extension, a regular file: a config itself named <code>*.lock</code> is refused
(the lock would overwrite it), and so is a symlink where the lock goes, by every
read and every write.</p><h2>The toolchain pin</h2><p>Every command but <code>zap lock</code> evaluates the config only with the <code>fgro</code> build
(Gro's runtime) whose blake3 the lock's <code>toolchain</code> records:</p><!><p><code>zap lock</code> writes it: it hashes the binary <code>--fgro</code> or <code>ZAP_FGRO</code> names,
evaluates the config with that binary, and records its blake3, whatever the
lock pinned before. It prints the pin, and the one it replaced when the pin
moved:</p><!><p>A moved pin reads <code>pinned fgro &lt;new> (was &lt;old>)</code>. Every other command reads the
pin before it evaluates:</p><ul><li><strong>no pin</strong>, because there is no lock or no <code>zap lock</code> has pinned one in it,
refuses the evaluation, exit 2, saying to run <code>zap lock</code>;</li><li><strong>a binary that hashes to something else</strong> refuses, exit 2: run <code>zap lock</code> to
pin the build you mean to use, or point <code>--fgro</code> at the pinned one. <code>zap update</code> doesn't re-pin it: moving the evaluator is <code>zap lock</code>'s alone, so
it shows up in the lock's diff by itself;</li><li><code>zap lock --check</code> reports a binary off its pin as a stale toolchain pin, exit
1, and evaluates nothing, so the entries go unchecked until it is pinned.</li></ul><p>A build of <code>fgro</code> is not reproducible across machines, so the pin names one
binary: another machine evaluates the config only with a copy of the same
bytes, or after its own <code>zap lock</code>, which shows in the lock's diff. An
unchanged binary isn't hashed in full on every command
(<a>On-disk state</a>).</p><p>A <code>"version": 1</code> lock has no toolchain pin: it reads, and every command refuses
until <code>zap lock</code> rewrites it. A <code>"version": 2</code> lock reads as it is; the next
write records it as version 3, which a <code>zap</code> build that reads only version 2 refuses. A
lock with a <code>version</code> newer than this <code>zap</code> reads is refused, <code>zap lock</code> included.</p><h2>Two kinds of fetched content</h2><p>A <code>file</code> with <code>remote</code> content, a <code>build</code>, whose source archive is fetched and
built, and an <code>apt_repo</code>, whose signing key is fetched and installed, take bytes
from a URL. Each is pinned by the <strong>blake3 of the
fetched bytes</strong>, so the same declaration always resolves to the same bytes. The
pin lives in one of two places:</p><table><thead><tr><th></th><th>Where the pin lives</th><th>Lock entry</th><th>How it moves</th></tr></thead><tbody><tr><td><strong>Vendored</strong></td><td>in the config: <code>blake3: '…'</code> on the <code>remote</code> content or the <code>source</code>, <code>key_blake3: '…'</code> on an <code>apt_repo</code></td><td>none</td><td>edit the hash in <code>zap.ts</code></td></tr><tr><td><strong>Tracked</strong></td><td>in <code>zap.lock</code>, next to <code>zap.ts</code></td><td>one per resource</td><td><code>zap update &lt;id></code> or <code>zap lock</code></td></tr></tbody></table><p>Vendored is self-contained: a URL and a hash, both in the config, and editing
the version means editing the hash. Tracked is the reviewed-upgrade path: bump
the version in the config, run <code>zap update</code>, and read the new pin in the lock
diff before committing both.</p><h2>What an entry holds</h2><!><p><code>kind</code> is <code>remote_file</code>, <code>build</code>, or <code>apt_key</code>. <code>blake3</code> is the pin, 64 lowercase hex with no prefix. <code>config_hash</code>, in the
same form, is the blake3 of the resource's declaration with the pin folded in
and Zap's resource-hash version ahead of it: the fixed point the entry was
minted for. It is how Zap knows an entry is <strong>stale</strong>: edit what the hash covers
(the URL, a <code>strip_components</code>, a <code>build</code>'s <code>run</code>, an <code>apt_repo</code>'s <code>source</code>) and the recomputed hash no
longer matches, so the pin is no longer known to be the pin for <em>this</em> declaration. It leaves out what doesn't change what the pin is the pin for: the
resource's identity (<code>id</code>, <code>name</code>, <code>depends_on</code>), an <code>auth</code> credential, and a <code>file</code>'s <code>validate</code> command. A new Zap version that changes what the hash covers
reads every entry stale once, until <code>zap update</code>.</p><p>The hash is unkeyed. It tells a stale entry from a current one, not a genuine
entry from a forged one: whoever can edit <code>zap.lock</code> can write a matching <code>config_hash</code> for any pin. The lock is trusted as reviewed input, like the
config beside it, so review its diff before committing it.</p><p><code>zap.lock</code> is committed, so the hash must not be a way to test a guess at a
secret. A reference that is a <a>secret</a> (by its use as an <code>auth</code> credential, by <code>mask()</code>, by its name, or by the form of its value) is
hashed as the fixed token <code>[MASKED:NAME]</code>, whatever its value. Consequences:</p><ul><li>Rotating a token in a tracked URL doesn't make the entry stale. The lock
verifies on a machine that doesn't have the secret when the entry's URL and
path hold no non-secret reference, and when the secret is one by more than the
form of its value (a variable secret only by that form has to be set).</li><li>A reference that only <em>looks</em> like a secret (<code>KEYCLOAK_VERSION</code>) loses its
staleness signal too. <code>zap lock</code>, <code>zap update</code>, and <code>zap lock --check</code> print a <code>note:</code> naming each reference addressed this way because of its name or the
form of its value, with the reason; <code>zap.unmask('NAME')</code> makes a non-secret
one count again.</li><li>Whether a reference is a secret can depend on its value: a URL is one only
while it holds a password, and a secret-named variable isn't one while it
holds a switch (<code>true</code>, <code>1</code>). An entry minted under one reading and checked
under the other never reads current: it reads stale, or unverifiable when the
variable is unset and only its value would make it a secret.</li></ul><p>Any other reference is hashed by its resolved value, with every secret value
the config references anywhere replaced by its token where it occurs inside it,
as the output masking replaces it: a <code>DOWNLOAD_URL</code> that carries the value of a <code>SIGNING_SECRET</code> the config also uses is hashed with that part as <code>[MASKED:SIGNING_SECRET]</code>, so its entry moves when the rest of the URL does and
not when the secret is rotated with it. A secret shorter than 8 characters, or any
form of it shorter than that (trimmed, or with its <code>\\n</code> decoded), is not replaced:
replacing <code>zig</code> wherever it occurs would move unrelated addresses with the
secret's value, and so few characters are guessable anyway. A secret can only
be replaced while it is set. While a variable the config uses as a secret (by its
use as a credential, <code>mask()</code>, or its name) is unset, <code>zap lock</code> and <code>zap update</code> don't mint an entry whose URL or path holds a non-secret reference, and name the
variable to set. Such an entry already in the lock is still checked: an address
that matches reads current, and only one that changed reads unverifiable, naming
the variable, since the change may be the secret's. A value that carries a secret
under an ordinary name (a <code>BASE_URL</code> with a token in it) that no secret reference
names should be listed in <code>mask()</code>. A <code>build</code>'s <code>run</code>, <code>env</code> values, and <code>verify</code> block are hashed as declared: a reference there counts as the reference, whatever
its value, so the entry moves only when the declaration does.</p><h2>Standing</h2><p>Every command that reads the lock classifies each tracked resource:</p><table><thead><tr><th>Standing</th><th>Meaning</th></tr></thead><tbody><tr><td>current</td><td>the entry's <code>config_hash</code> matches the resource</td></tr><tr><td>missing</td><td>the resource is tracked but has no entry</td></tr><tr><td>stale</td><td>the resource changed since the entry was minted</td></tr><tr><td>unverifiable</td><td>a variable the hash depends on is unset: a non-secret reference, or a secret a non-secret value could hold</td></tr><tr><td>orphan</td><td>an entry for a resource the config no longer declares (warn only)</td></tr></tbody></table><p><code>zap lock --check</code> reports the standing as its gate and exits 1 for missing,
stale, or unverifiable. The read-only commands (<code>plan</code>, <code>detect</code>, <code>status</code>, the
deploy preflight) lead their output with a <code>LOCK</code> banner for the same findings. <code>apply</code> refuses a stale or unverifiable entry instead, as does a <code>deploy</code> wetrun's preflight, with exit 2 (<a>cli.md</a> has every command's exit
codes).</p><h2>Who writes, who reads</h2><p>Only <code>apply --wetrun</code> and the lock verbs write the file. Each keeps the
toolchain pin it found, except <code>zap lock</code>, which sets it. Every other command but <code>zap version</code> validates the file, and refuses one that doesn't parse.</p><p>A write takes an exclusive <code>flock</code> on <code>zap.lock</code> itself, opened for writing, so
concurrent writers take turns. <code>apply --wetrun</code> and <code>zap update</code> merge into the
file as it stands when they hold it, so neither loses entries another wrote; <code>zap lock</code> rewrites the file whole, reading the old one only for the pin it
replaces and to refuse one newer than it reads, so it rebuilds one that no
longer parses, such as one left with merge-conflict markers. A <code>zap.lock</code> is
refused (<code>zap.lock is not writable</code>) for a user who can't write it, rather than
replaced, and a lock Zap can't create says its directory isn't writable. A <code>zap.lock</code> that is empty reads as no lock.</p><ul><li><strong><code>zap apply</code></strong>: a dry run resolves any <em>missing</em> tracked pin over the
network, the one network read a dry run does, and reports it as <code>resolved, not yet written to zap.lock</code>. A wetrun writes the resolved lock
before executing, so an apply is never recorded without its intent. A <strong>stale</strong> or <strong>unverifiable</strong> entry is an error on apply, never
auto-reconciled: the message says what to run.</li><li><strong>No pin is minted from a URL Zap can't fully resolve.</strong> If a tracked URL
references a variable that is unset or empty, <code>zap lock</code> refuses (exit 2) and <code>zap update</code> fails that entry, naming the variable; nothing is fetched with
the reference blank. A dry <code>zap apply</code> holds the resource instead (exit 1),
and a wetrun's env gate has already stopped the run.</li><li><strong><code>zap lock</code></strong>: rebuild. Pins the toolchain, re-fetches every tracked source,
re-mints every entry, drops orphans, rewrites the file. All or nothing. The
only verb that prunes, and the only one that moves the toolchain pin.</li><li><strong><code>zap lock --check</code></strong>: offline classification, no network, no detection,
after the toolchain pin is checked against the binary.</li><li><strong><code>zap update [ids…]</code></strong>: re-fetch the named resources, or all tracked ones.
An entry is rewritten when its pin advanced <em>or</em> when its <code>config_hash</code> was
stale (same bytes, edited resource), so the <code>zap update &lt;id></code> the stale error
prescribes always clears it. Each advance is written as it happens; a failure
later in the run keeps the earlier advances.</li><li><strong><code>plan</code>, <code>detect</code>, <code>status</code>, deploy's preflight</strong>: read-only. They never
mint, and they <strong>withhold</strong> any pin that isn't current. The resource then
behaves exactly like one with no pin: <code>undetermined</code>, held out of the
changeset, exit 1 (the preflight bails with exit 2), so a stale pin can't make <code>plan</code> report "converged" for a config <code>apply</code> refuses.</li></ul><h2>What detection compares</h2><p>The pin is the desired side of the comparison; detection never fetches. An
unextracted <code>remote</code> file is compared by digest against the pinned bytes; an
extracted one (<code>extract: tar.*</code>) through its <strong>extract sentinel</strong>, a <code>.zap_remote_hash</code> file in the destination recording a digest of the tarball pin
and the extract form; a <code>build</code> through its <strong>provenance sidecar</strong>, <code>&lt;output>.zap-build</code>, recording a digest of the source pin and how it is built
(<code>extract</code>, <code>run</code>, <code>cwd</code>, <code>env</code>); an <code>apt_repo</code>'s key by the blake3 of the key
file's bytes against its pin. A pin change re-extracts, rebuilds, or reinstalls
the key, and so does an edit to what the digest covers. The details are in <a>detection.md</a> and <a>detection.md</a>.</p><h2>Verification</h2><p>A <code>build</code> source that declares <code>verify</code> (minisign) has its signature checked <strong>before</strong> the archive is cached or pinned, so a tampered fetch never becomes a
pin; a cache hit re-hashes the bytes against the pin instead. The fields and
the trust argument: <a>resources.md</a>.</p><h2>What the lock does not cover</h2><p>Package versions, installer versions, and anything else that isn't a tracked <code>remote</code> file, <code>build</code> source, or <code>apt_repo</code> key. A <code>package</code> is detected by the manager's query through
the package manager; an <code>installer</code> by its <code>check</code> path. Drift detection for
every other kind is the kind's own live reads.</p><h2>On-disk state</h2><p>Zap keeps its own working state under <code>~/.zap</code>, or <code>$ZAP_HOME</code>, separate from
the config and the env file. Either path must be absolute; an empty <code>ZAP_HOME</code> counts as unset. Every directory Zap keeps state in (the root, <code>cache/</code> and
everything under it, <code>ssh/</code>) is yours alone (mode <code>700</code>) and every file it
writes there is <code>600</code>; <code>bin/</code> is the installer's, and yours. Zap tightens a state
directory it finds looser, and refuses to run (exit 2) over one that is a
symlink, isn't a directory, belongs to another user, or can't be opened, since
the records in it decide what a wetrun may execute:</p><table><thead><tr><th>Path</th><th>Holds</th></tr></thead><tbody><tr><td><code>bin/zap</code></td><td>the installed binary</td></tr><tr><td><code>bin/fgro</code></td><td>where <a>install.md</a> suggests keeping the <code>fgro</code> build <code>ZAP_FGRO</code> names, apart from Gro's build output; Zap never writes it</td></tr><tr><td><code>cache/&lt;config-slug>/last_run/&lt;host>.json</code></td><td>the last-run report for this config on this host, latest only. A host that isn't a safe file name (a path separator, say) is filed as <code>host-&lt;short-hash>.json</code>. No report is kept for a host that resolves through a masked reference.</td></tr><tr><td><code>cache/&lt;config-slug>/deploy_preview/&lt;host>.json</code></td><td>the deploy preview for this config on this host: the <code>plan_hash</code> the last <code>zap deploy</code> dry run (or refused wetrun) showed, when, and which pass. Withdrawn by a deploy wetrun before its first step.</td></tr><tr><td><code>cache/&lt;config-slug>/eval/</code></td><td>the eval cache: the config's evaluated JSON beside a manifest of its path, the driver and <code>fgro</code> build it ran on, each file the evaluation read with its blake3, each path a resolution found empty, and the evaluated JSON's own blake3; an entry is served only for the config it was evaluated from, and only the JSON its manifest names. See <code>ZAP_EVAL_CACHE</code> in <a>cli.md</a>; <code>--no-cache</code> bypasses it.</td></tr><tr><td><code>cache/fgro_pins/</code></td><td>the <code>fgro</code> binary's blake3, keyed by the file's inode, size and times, so an unchanged binary isn't hashed in full on every command (<a>The toolchain pin</a>)</td></tr><tr><td><code>cache/files/&lt;blake3>/&lt;name></code></td><td>the content cache: bytes for <code>remote</code> files and <code>build</code> sources, by content address, checked against their blake3 on every read</td></tr><tr><td><code>ssh/</code></td><td>SSH <code>ControlMaster</code> sockets for remote targets (<a>targets.md</a>)</td></tr></tbody></table><p><code>bin/</code> is always <code>~/.zap/bin</code>: <code>cargo xtask install</code> doesn't read <code>ZAP_HOME</code>.</p><p><code>ZAP_FGRO</code>, which names the <code>fgro</code> binary every config is evaluated with, is held
tighter than <code>ZAP_HOME</code>: it must be an absolute path, and an empty one is an
error (exit 2), not an unset one, since it names what runs your config
(<a>install.md</a>). Under <code>sudo</code>, the state home, pin
cache included, is the one <code>sudo</code>'s <code>HOME</code> gives Zap.</p><p>None of this is part of the declared state or the plan hash, and none of it
stands in for reading the target. <code>zap.lock</code> is the exception by design: it
lives next to <code>zap.ts</code> and is committed, because it records intent.</p>`,1);function b(c,b){p(b,!0);let x=h(`lock`);d(`3uxscg`,e=>{t(()=>{n.title=`The lock file and Zap's state — zap`})}),g(c,{get tome(){return x},children:(t,n)=>{v(t,{children:(t,n)=>{var c=y(),d=a(c),f=e(i(d),5);o(),s(d);var p=e(d,2);u(p,`id`,`the-toolchain-pin`);var h=e(p,2);_(h,{lang:`json`,dangerous_raw_html:`<span class="token_punctuation">{</span>
  <span class="token_property">"version"</span><span class="token_operator">:</span> <span class="token_number">3</span><span class="token_punctuation">,</span>
  <span class="token_property">"toolchain"</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>
    <span class="token_property">"fgro_blake3"</span><span class="token_operator">:</span> <span class="token_string">"…"</span>
  <span class="token_punctuation">},</span>
  <span class="token_property">"entries"</span><span class="token_operator">:</span> <span class="token_punctuation">{}</span>
<span class="token_punctuation">}</span>`});var g=e(h,2);_(g,{lang:null,content:`$ zap lock
pinned fgro d5d10656aab9b1126949c67260afe0f06fbb208230306efd245186f2c4462c22
wrote zap.lock (no eligible resources)`});var v=e(g,3),b=e(i(v),5);u(b,`href`,`#on-disk-state`),o(),s(v);var x=e(v,2);u(x,`id`,`two-kinds-of-fetched-content`);var S=e(x,4);u(S,`id`,`what-an-entry-holds`);var C=e(S);_(C,{lang:`json`,dangerous_raw_html:`<span class="token_punctuation">{</span>
  <span class="token_property">"version"</span><span class="token_operator">:</span> <span class="token_number">3</span><span class="token_punctuation">,</span>
  <span class="token_property">"toolchain"</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>
    <span class="token_property">"fgro_blake3"</span><span class="token_operator">:</span> <span class="token_string">"…"</span>
  <span class="token_punctuation">},</span>
  <span class="token_property">"entries"</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>
    <span class="token_property">"pgdg"</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>
      <span class="token_property">"kind"</span><span class="token_operator">:</span> <span class="token_string">"apt_key"</span><span class="token_punctuation">,</span>
      <span class="token_property">"config_hash"</span><span class="token_operator">:</span> <span class="token_string">"…"</span><span class="token_punctuation">,</span>
      <span class="token_property">"blake3"</span><span class="token_operator">:</span> <span class="token_string">"…"</span>
    <span class="token_punctuation">},</span>
    <span class="token_property">"zig"</span><span class="token_operator">:</span> <span class="token_punctuation">{</span>
      <span class="token_property">"kind"</span><span class="token_operator">:</span> <span class="token_string">"remote_file"</span><span class="token_punctuation">,</span>
      <span class="token_property">"config_hash"</span><span class="token_operator">:</span> <span class="token_string">"…"</span><span class="token_punctuation">,</span>
      <span class="token_property">"blake3"</span><span class="token_operator">:</span> <span class="token_string">"…"</span>
    <span class="token_punctuation">}</span>
  <span class="token_punctuation">}</span>
<span class="token_punctuation">}</span>`});var w=e(C,3),T=e(i(w),2);o(7),s(w);var E=e(w,3);u(E,`id`,`standing`);var D=e(E,3),O=e(i(D),14);o(),s(D);var k=e(D);u(k,`id`,`who-writes-who-reads`);var A=e(k,4);u(A,`id`,`what-detection-compares`);var j=e(A),M=e(i(j),25),N=e(M,2);o(),s(j);var P=e(j);u(P,`id`,`verification`);var F=e(P),I=e(i(F),7);o(),s(F);var L=e(F);u(L,`id`,`what-the-lock-does-not-cover`);var R=e(L,2);u(R,`id`,`on-disk-state`);var z=e(R,2),B=e(i(z)),V=e(i(B)),H=e(i(V)),U=e(i(H));o(5),s(H),s(V);var W=e(V,3),G=e(i(W)),K=e(i(G),5);o(3),s(G),s(W);var q=e(W),J=e(i(q)),Y=e(i(J),3);u(Y,`href`,`#the-toolchain-pin`),o(),s(J),s(q);var X=e(q,2),Z=e(i(X)),Q=e(i(Z),3);o(),s(Z),s(X),s(B),s(z);var $=e(z,2),ee=e(i($),6);o(7),s($),o(),r((e,t,n,r,i,a,o,s,c,l)=>{u(f,`href`,e),u(T,`href`,t),u(O,`href`,n),u(M,`href`,r),u(N,`href`,i),u(I,`href`,a),u(U,`href`,o),u(K,`href`,s),u(Q,`href`,c),u(ee,`href`,l)},[()=>m(`docs/concepts#the-lock-file`),()=>m(`docs/env#secrets`),()=>m(`docs/cli`),()=>m(`docs/detection#content-is-compared-by-digest`),()=>m(`docs/detection#build-exact-provenance-not-a-version-string`),()=>m(`docs/resources#verification`),()=>m(`docs/install#getting-fgro`),()=>m(`docs/cli#environment-variables-zap-reads`),()=>m(`docs/targets#how-zap-reaches-a-remote-host`),()=>m(`docs/install#getting-fgro`)]),l(t,c)},$$slots:{default:!0}})},$$slots:{default:!0}}),f()}export{b as t};