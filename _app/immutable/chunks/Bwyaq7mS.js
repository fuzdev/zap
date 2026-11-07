import{$ as e,G as t,J as n,K as r,X as i,Z as a,dt as o,ft as s,j as c,k as l,l as u,m as d,ot as f,st as p}from"./CkSeWg2M.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as g}from"./k6TRNp0w.js";import{t as _}from"./DH_LefOd.js";import{t as v}from"./BzaAmULn.js";var y=c(`<p>How values that vary per machine, or must stay secret, reach a config without
being written into it. The sandbox that makes this necessary is described in <a>configs.md</a>.</p><h2>References</h2><p>A config never reads the environment. It writes a reference instead, with <code>zap.env('NAME')</code>:</p><!><p>The reference stays inert in the declaration and in the plan. Zap resolves it
from the operator environment when it acts, in these fields only:</p><table><thead><tr><th></th><th>Resolves a reference</th><th>Takes none: write the value out</th></tr></thead><tbody><tr><td>target</td><td><code>host</code>, <code>user</code>, <code>bootstrap_user</code></td><td><code>port</code>, <code>key_path</code>, <code>home</code></td></tr><tr><td>paths</td><td>resource paths; a <code>package</code>'s <code>check</code> and an <code>installer</code>'s <code>check</code> when they are paths</td><td>a <code>swap</code>'s <code>path</code>; an <code>apt_repo</code>'s <code>key_path</code> and <code>list_file</code>; a <code>script</code>'s or <code>build</code>'s <code>cwd</code>; <code>deploy.path</code></td></tr><tr><td>content</td><td>a <code>template</code> file's <code>vars</code> values</td><td>inline content and a template's body (written as declared)</td></tr><tr><td>commands</td><td><code>script</code>, <code>installer</code>, <code>build</code>, and <code>pipeline</code> commands; an <code>installer</code>'s <code>shell</code>; a <code>file</code>'s <code>validate</code>; a <code>script</code>'s and a <code>build</code>'s <code>env</code> values</td><td>a <code>verify</code> assertion and a <code>package</code>'s <code>check</code> when it is a command (run as written)</td></tr><tr><td>names</td><td>a <code>database</code>'s identifiers and <code>auth.hosts</code></td><td>a package name, a service name, <code>deploy.service</code>, a <code>user</code>'s <code>shell</code>, <code>ssh_keys.keys</code>, and <code>sudo</code> <code>commands</code>, a named firewall profile</td></tr><tr><td>URLs</td><td>a <code>remote</code> URL and its <code>auth</code> token, a <code>build</code> source's signature URL, an <code>installer</code>'s URL, an <code>apt_repo</code>'s <code>key_url</code></td><td>an <code>apt_repo</code>'s <code>source</code></td></tr><tr><td>other</td><td>a <code>swap</code>'s <code>size</code>, <code>deploy.health.domain</code></td><td><code>deploy.health.path</code>, and every field not listed</td></tr></tbody></table><p>A reference where none is taken fails when Zap reads the config, naming the
resource, the field, and what to use instead:</p><!><p>A reference in a command is replaced as text: put it inside single quotes, or
hand the command an arbitrary value through <code>env</code>, which is quoted after it
resolves. The values Zap refuses in a command, and why: <a>security.md</a>. A template's <code>vars</code> value can't hold a
line break, which would add a line to the file
(<a>resources.md</a>). An env-file value can't hold a NUL. A
value holding U+FDD0 or
U+FDD1 is refused wherever it would be substituted, an <code>env</code> value included: a
value is substituted once and can't carry a reference of its own.</p><p><code>zap.env('NAME')</code> returns a string, so a reference composes like one:</p><!><p>That path has a reference in it, and a recipe can splice a value it was handed
without knowing whether it is one. A recipe
makes its own with <code>env_ref('NAME')</code>, imported from <code>@fuzdev/zap/env_ref.ts</code>.
The name must be an environment variable name (letters, digits, and <code>_</code>, not
starting with a digit).</p><p>While the config is evaluated that string is opaque. It holds a marker, not
the value, so interpolating and concatenating it are the only things to do with
it:</p><ul><li>slicing it, splitting it, or changing its case damages the marker, and the
config fails to evaluate, naming the field;</li><li>a regular-expression replace that strips non-word characters, or <code>encodeURIComponent</code>, silently turns it into ordinary text;</li><li>code that inspects a value (its length, its first character) sees the marker.</li></ul><p>A reference is the string <code>zap.env</code> or <code>env_ref</code> returns. Text that merely
looks like one is text: <code>$$</code>, <code>$$NAME$$</code>, <code></code>, and <code></code> in a command
or a file are what they say. The two characters the marker is built from (U+FDD0 and U+FDD1) can't
appear in a config's own strings; content that holds them comes from a <code>source</code> or <code>remote</code> file.</p><p>Previews and messages show a reference as <code></code>:</p><!><p>What each reference a plan uses resolves to is printed once, in a <code>references:</code> block under the target, and is part of the plan and its hash: a plain
reference's value, or for a <a>secret</a> only that it is one. So a value
you wouldn't want in a preview or a CI log belongs under a name Zap reads as a
secret, or in <code>zap.mask</code>.</p><!><p>Text in a command can spell <code></code> too. Where it matters which it is, the <code>target:</code> line and a template's <code>vars</code> print the exact form, <code></code>,
and <code>plan_hash</code> covers it.</p><p>A command, a path, or an SSH destination that still holds an unresolved
reference is never run, touched, or connected to: Zap refuses first.</p><h3>Target-categorized resolution</h3><p>Two kinds of placeholder resolve against two different machines:</p><table><thead><tr><th>Placeholder</th><th>Resolves against</th><th>In the plan</th></tr></thead><tbody><tr><td><code>zap.env('NAME')</code></td><td>the <strong>operator's</strong> environment</td><td>as a reference; the value arrives when Zap acts</td></tr><tr><td><code>~</code>, <code>$HOME</code></td><td>the <strong>target's</strong> home: <code>target.home</code> remotely, your own locally</td><td>as written</td></tr></tbody></table><p>So a resource's part of the plan doesn't depend on the environment or the
target's home, and a remote path that needs a home with none declared is
undetermined rather than guessed. The home itself is part of the plan beside
it: a remote one as the declared target's <code>home</code>, your own as the local plan's <code>home:</code> line. A resource's resolved values reach the hashes
of the last-run report and, for a tracked source, the lock.</p><p>The target's <code>host</code>, <code>user</code>, and <code>bootstrap_user</code> resolve from references too;
they are connection context (<a>targets.md</a>).</p><h2>The env file</h2><p>Every config command accepts <code>--env-file &lt;path></code>, a file of <code>NAME=VALUE</code> lines
loaded into the operator environment before anything resolves. A name set in
both the file and your shell takes the file's value:</p><!><p>One explicit file, no auto-discovery, no <code>.env</code> plus <code>.env.&lt;mode></code> merging.
Keep env files out of version control and commit a <code>.example</code> with the names.
Name it for what it is, say <code>zap.env</code> or <code>zap.production.env</code>; don't reuse the
name of an env file your app reads on the host, which <code>deploy.shared</code> may be
linking into releases.</p><p>The format is a strict subset of dotenv: Zap reads only lines the common
loaders agree on, and a line it doesn't understand is an error instead of a
guess. (A loader that interpolates still reads a <code>$</code> its own way.)</p><table><thead><tr><th>Line</th><th>Reads as</th></tr></thead><tbody><tr><td>blank, or beginning <code>#</code></td><td>nothing</td></tr><tr><td><code>NAME=value</code></td><td>the value to the end of the line, surrounding whitespace trimmed</td></tr><tr><td><code>NAME='value'</code></td><td>the value as written</td></tr><tr><td><code>NAME="value"</code></td><td>the value, with <code>\\\\</code>, <code>\\"</code>, <code>\\n</code>, and <code>\\r</code> decoded</td></tr><tr><td><code>export NAME=value</code></td><td>the same as without <code>export</code></td></tr></tbody></table><p>A name is letters, digits, and <code>_</code>, not starting with a digit. There is no
interpolation (<code>$OTHER</code> is text) and no value spanning lines. These don't load:
a line with no <code>=</code>, a name that isn't one (<code>export</code> counts only before a
space), a name assigned twice, a quote left open or followed by anything but a
comment, an unquoted value that begins with <code>#</code> or holds one after whitespace
(quote the value, or move the comment to its own line), an unquoted value
ending in a backslash or holding a control character other than a tab, or a
Unicode line or paragraph separator (U+2028, U+2029), and a NUL in an assignment. Whitespace around the <code>=</code> is
trimmed, and a byte-order mark at the start is skipped. The error names the
file, the line, and the name when the line has one, and never any part of a
value or of the line.</p><p>Zap warns, once per command, about an env file its group or everyone can write
(whoever can rewrite it chooses the host a deploy goes to), and about one they
can read when it holds a secret by its name or the form of its value (the file
is read before the config, so a variable only <code>mask()</code> lists doesn't count),
saying which. <code>chmod 600</code> answers both.</p><h2>Unset references</h2><p>A reference with no value, or an empty one, is handled by what the command does:</p><ul><li><strong>A wetrun (<code>apply</code> or <code>deploy</code>) refuses to start.</strong> Every referenced variable
must be set and non-empty, or the run fails before any side effect. An empty <code>DATABASE_URL</code> would otherwise be written into a <code>.env</code> file as nothing.</li><li><strong>A comparing dry run (<code>plan</code>, <code>apply</code>, <code>detect</code>) is unverifiable.</strong> Detection
resolves references into the desired side of its comparison, so an unset one
makes the answer unsound in both directions: it can hide drift (the target
already holds the empty value) and invent it (the target holds the real one).
The command leads with the banner and exits 1:<!><p>The check covers what the comparison resolves: the resources, and the
target's <code>host</code>, <code>user</code>, and <code>bootstrap_user</code>. The user the run connects as
is held to more: if it resolves to nothing the command stops before it
connects (below), since <code>ssh</code> would pick an account of its own. It ignores the <code>deploy</code> block and a fetch credential (the <code>auth</code> token of a <code>remote</code> file or
a <code>build</code> source). A <code>database</code>'s <code>auth.hosts</code> is part of the comparison and
is covered.</p></li><li><strong>A deploy dry run warns.</strong> It compares nothing (the preflight is
wetrun-only), so its rendered plan is sound.</li><li><strong>A remote <code>host</code>, or a declared connecting user, that resolves to nothing is
an error before any connection.</strong> Zap won't SSH to nowhere, or as whichever
account <code>ssh</code> picks: <code>plan</code>, <code>detect</code>, <code>apply</code>, and <code>deploy</code> exit 2, naming
the variable that is unset or empty.</li></ul><h3>Unverifiable</h3><p>The banner above is the <code>unverifiable</code> verdict: the desired side of a
comparison couldn't be built. It is the twin of <code>undetermined</code>, where the
observed side couldn't be read. Both outrank "converged" and "drifted" in the
exit code, because neither claim was established.</p><h2>Secrets</h2><p>One rule decides whether a reference is a secret, and everything that treats
secrets differently asks it. In order:</p><ol><li><strong>Where it is used.</strong> A reference in a <code>remote</code> file's or a <code>build</code> source's <code>auth</code> is a secret, whatever it is called.</li><li><strong>What you said.</strong> <code>zap.unmask('NAME')</code> makes a reference plain, and <code>zap.mask('NAME')</code> makes it a secret. Unmasking a reference used as an <code>auth</code> credential is an error.</li><li><strong>Its name</strong>, by the rule in <a>Secret names</a> below.</li><li><strong>The form of its value.</strong> A value is a secret, whatever its name, when it
holds a URL with a password (<code>postgres://app:…@db/app</code>, so a <code>DATABASE_URL</code> needs no <code>mask</code>), an <code>http</code> or <code>https</code> URL with a user, <code>git+https</code> included
(<code>https://&lt;token>@git.example.com/…</code>: HTTP reads a user only as a credential,
where <code>ssh://git@…</code> and <code>postgres://app@…</code> name an account), a PEM private
key, or an HTTP authorization value (<code>Basic</code> with its encoded <code>user:password</code>, or <code>Bearer</code> with a token of 16 characters or more, alone or
as an <code>Authorization:</code> or <code>Proxy-Authorization:</code> header line). A password
holding an unencoded <code>?</code> or <code>#</code> still counts when no <code>@</code> comes before that
character (<code>postgres://app:p#ss@db/app</code>, as libpq reads it: up to the first <code>@</code> after it), unless what precedes it is all digits, which reads as a port. A password
in a query string or in <code>key=value</code> form, and a secret in a URL's path (a
webhook's), aren't recognized: name the variable for what it is or <code>zap.mask</code> it.</li></ol><p>What is masked is a value Zap resolves: a name no field references registers
nothing, so <code>zap.mask</code> doesn't scrub a value a command reads from the target's
own environment.</p><h3>Secret names</h3><p>Case-insensitive. A name is a secret's when it:</p><table><thead><tr><th></th><th>Words</th></tr></thead><tbody><tr><td>holds anywhere</td><td><code>SECRET</code>, <code>PASSWORD</code>, <code>TOKEN</code>, <code>KEY</code>, <code>CREDENTIAL</code></td></tr><tr><td>has a last word ending in</td><td><code>PASS</code>, <code>PASSWD</code>, <code>PASSPHRASE</code>, <code>PASSCODE</code>, <code>PWD</code>, <code>BINDPW</code>, <code>ROOTPW</code> (ordinary words like <code>BYPASS</code> and <code>COMPASS</code>, and the shell's own <code>PWD</code> and <code>OLDPWD</code>, aside)</td></tr><tr><td>has a last word that is</td><td><code>PW</code>, <code>PAT</code>, <code>DSN</code>, <code>AUTH</code>, <code>PRIVATE</code>, <code>SALT</code>, <code>COOKIE</code>, <code>SESSION</code>, <code>JWT</code>, <code>CRED</code>, <code>PSK</code>, <code>WEBHOOK</code>; or <code>URL</code> or <code>URI</code> after <code>WEBHOOK</code> or <code>WEBHOOKS</code></td></tr></tbody></table><p>The last word is the part after the final <code>_</code>, passing over a trailing number
written apart or glued on (<code>SMTP_PASS_2</code>, <code>DB_PASS2</code>; <code>AUTH0</code> is a name, not <code>AUTH</code>), a version (<code>DB_PASS_V2</code>), and a qualifier naming an environment or a
rotation (<code>PROD</code>, <code>PRODUCTION</code>, <code>STAGING</code>, <code>STAGE</code>, <code>DEV</code>, <code>DEVELOPMENT</code>, <code>TEST</code>, <code>TESTING</code>, <code>QA</code>, <code>UAT</code>, <code>OLD</code>, <code>PREV</code>, <code>PREVIOUS</code>, <code>NEW</code>, <code>NEXT</code>, <code>CURRENT</code>, <code>PRIMARY</code>, <code>SECONDARY</code>), so <code>DB_PASS_PROD</code> is a secret. A plural reads
as its word (<code>DB_CREDS</code>, <code>HASH_SALTS</code>), except for <code>AUTH</code>, <code>PRIVATE</code>, <code>SESSION</code>, <code>COOKIE</code>, <code>WEBHOOK</code>, and a word ending in <code>PASS</code>, whose plurals count or switch
something (<code>MAX_SESSIONS</code>, <code>MAX_PASSES</code>).</p><p>So <code>DB_PASS</code>, <code>GITHUB_PAT</code>, <code>SENTRY_DSN</code>, and <code>SLACK_WEBHOOK_URL</code> are secrets,
and <code>AUTH_HOST</code>, <code>PRIVATE_IP</code>, and <code>SESSION_TIMEOUT</code> aren't. A secret-named
variable is plain while its value is a switch (<code>true</code>, <code>false</code>, <code>yes</code>, <code>no</code>, <code>on</code>, <code>off</code>, or a single digit, in any case, whitespace around it ignored), so <code>ENABLE_AUTH=true</code> masks nothing.</p><h3>Masked hosts and review</h3><p>A <code>target.host</code>, a connecting user, or a <code>deploy.health.domain</code> behind a secret
reference makes a plan no review can bind, since its hash would name no one
machine or be computed from the secret. <code>zap apply --wetrun</code> and <code>zap deploy --wetrun</code> refuse it before anything runs, a dry run shows the plan
under an <code>UNBINDABLE</code> note with no <code>plan_hash</code> and records no preview, and a
masked host keeps no last-run report. The message names the cause:</p><table><thead><tr><th>The reference is a secret because of</th><th>Way out</th></tr></thead><tbody><tr><td>its name or the form of its value</td><td><code>zap.unmask('NAME')</code> if it isn't one, or write the value literally</td></tr><tr><td>the config's <code>zap.mask('NAME')</code></td><td>drop the <code>mask</code></td></tr><tr><td>its use as a fetch credential too</td><td>reference another variable in the host, user, or domain, or write the value literally</td></tr><tr><td>a registered secret carried in its value</td><td>take the value from a literal, or from a variable that carries none</td></tr></tbody></table><h3>What masking covers</h3><p>A secret's resolved value is <strong>masked</strong> out of everything Zap prints or writes:
the text report, <code>--json</code> events, warnings, held reasons, drift observations,
deploy step output, and errors. Masking is by value. Besides the value itself
Zap looks for it trimmed, URL-encoded, JSON-escaped, and single-quoted for a
shell as Zap's own commands carry it (each <code>'</code> written <code>'\\''</code>); for each line of 24
characters or more of a value that spans several (a PEM key, with its <code>\\n</code> decoded when it was written on one line; the <code>-----BEGIN…-----</code> lines aside);
and for the password or token inside a URL or an authorization value, when that
is 8 characters or more. A password that also appears elsewhere in its own
value (<code>postgres://app:postgres@db/app</code>) is an ordinary word and is masked only
as part of the whole. A secret a tool prints in any other form (the address <code>ssh</code> resolved a secret
host name to, a URL it rewrote around a short password) is not found.
The executor itself never sees a masked string; masking
happens where output is consumed. A plan's steps hold only the inert
reference; its <code>references:</code> block holds the value of a plain one, with any
secret inside that value masked, and for a secret only the fact. Commands reach their shell on stdin, so a
resolved value is on no <code>ssh</code> or shell argv
(<a>security.md</a>). There is no <code>--show-secrets</code>.</p><p>The same rule decides how <code>zap.lock</code> addresses a tracked source: a secret
reference is hashed as a fixed token, any other by its value
(<a>lock.md</a>).</p><p>The <strong>last-run report</strong> on disk is masked the same way. Each resource's hash
takes a secret reference as a fixed <code>[MASKED:NAME]</code> token and masks every
registered secret out of any other value, so the report can't be used to test a
guess at a secret, and a changed secret value isn't visible to <code>zap status</code> (which says so beside each resource that references one). <code>status</code> rebuilds
its masker from its own environment, so for an exact "unchanged since" it needs
the same env the run had, secrets included; without one it fails closed to
"changed since".</p><p>A <strong>literal secret</strong> in a config is rejected by every command: when a value that
is both referenced and resolvable in the current environment also
appears written out in the config, the secret gate fails, naming the field and
the variable and showing none of the text. It looks for a secret's whole value,
8 characters or more: a shorter one turns up in ordinary text by chance. It is
best-effort by design, so it never fails spuriously on a machine that simply
lacks the secret.</p>`,1);function b(c,b){p(b,!0);let x=h(`env`);d(`ztojx8`,e=>{t(()=>{n.title=`Environment and secrets — zap`})}),g(c,{get tome(){return x},children:(t,n)=>{v(t,{children:(t,n)=>{var c=y(),d=a(c),f=e(i(d));o(),s(d);var p=e(d);u(p,`id`,`references`);var h=e(p,2);_(h,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">target</span><span class="token_punctuation">({</span>host<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'DEPLOY_HOST'</span><span class="token_punctuation">),</span> user<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'DEPLOY_USER'</span><span class="token_punctuation">),</span> package_manager<span class="token_operator">:</span> <span class="token_string">'apt'</span><span class="token_punctuation">});</span>
zap<span class="token_punctuation">.</span><span class="token_function">file</span><span class="token_punctuation">({</span>
	id<span class="token_operator">:</span> <span class="token_string">'env'</span><span class="token_punctuation">,</span>
	path<span class="token_operator">:</span> <span class="token_string">'/srv/app/shared/.env'</span><span class="token_punctuation">,</span>
	content<span class="token_operator">:</span> <span class="token_punctuation">{</span>type<span class="token_operator">:</span> <span class="token_string">'template'</span><span class="token_punctuation">,</span> template<span class="token_operator">:</span> <span class="token_string">'DATABASE_URL={{url}}\\n'</span><span class="token_punctuation">,</span> vars<span class="token_operator">:</span> <span class="token_punctuation">{</span>url<span class="token_operator">:</span> zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'DATABASE_URL'</span><span class="token_punctuation">)}},</span>
<span class="token_punctuation">});</span>`});var g=e(h,4);_(g,{lang:null,content:"error: config did not match the zap schema (/home/ops/infra/zap.ts): 2 references in fields that take none:\n         - resource `motd`: `content.content` takes no reference: the content is written as declared; put the value in a template's `vars`, which resolve\n         - resource `work`: `cwd` takes no reference: zap enters a working directory as declared and never resolves it; write the path out"});var v=e(g),b=e(i(v),3),x=e(b,4);o(3),s(v);var S=e(v,2);_(S,{lang:`ts`,dangerous_raw_html:`zap<span class="token_punctuation">.</span><span class="token_function">directory</span><span class="token_punctuation">({</span>id<span class="token_operator">:</span> <span class="token_string">'data'</span><span class="token_punctuation">,</span> path<span class="token_operator">:</span> <span class="token_template_string"><span class="token_template_punctuation token_string">\`</span><span class="token_string">/srv/</span><span class="token_interpolation"><span class="token_interpolation_punctuation token_punctuation">\${</span>zap<span class="token_punctuation">.</span><span class="token_function">env</span><span class="token_punctuation">(</span><span class="token_string">'APP'</span><span class="token_punctuation">)</span><span class="token_interpolation_punctuation token_punctuation">}</span></span><span class="token_string">/data</span><span class="token_template_punctuation token_string">\`</span></span><span class="token_punctuation">});</span>`});var C=e(S,4),w=e(i(C),9);w.textContent="${NAME}";var T=e(w,2);T.textContent=`{env:NAME}`,o(5),s(C);var E=e(C),D=e(i(E));D.textContent=`{env:NAME}`,o(),s(E);var O=e(E);_(O,{lang:null,content:`  [+] conf  (file)
      path: {env:APP_DIR}/app.conf
      content: template (47 bytes, sha512 527b3af39db7aeb8…), vars {"domain":{"$env":"DEPLOY_DOMAIN"},"key":{"$env":"API_KEY"},"port":8080}`});var k=e(O),A=e(i(k),3);u(A,`href`,`#secrets`),o(3),s(k);var j=e(k);_(j,{lang:null,content:`  references:
    API_KEY is a secret: its value is not shown, and no part of it is in the plan or its hash
    APP_DIR = /srv/app
    DEPLOY_DOMAIN = app.example.com`});var M=e(j),N=e(i(M));N.textContent=`{env:NAME}`;var P=e(N,6);P.textContent=`{"$env":"NAME"}`,o(3),s(M);var F=e(M,2);u(F,`id`,`target-categorized-resolution`);var I=e(F,4),L=e(i(I),7);o(),s(I);var R=e(I);u(R,`id`,`the-env-file`);var z=e(R,2);_(z,{lang:`sh`,content:`zap apply --env-file zap.env
zap deploy --env-file zap.env --wetrun`});var B=e(z,6);u(B,`id`,`unset-references`);var V=e(B,2),H=e(i(V)),U=e(i(H),2);_(U,{lang:null,content:`UNVERIFIABLE — 2 referenced variable(s) are unset or empty, so this comparison cannot be trusted:
    DATABASE_URL, SMTP_PASSWORD
an unset reference resolves to an empty string, which can both hide real drift and invent drift that isn't there.
provide them (--env-file or the environment) and re-run.`}),o(),s(H),o(2),s(V);var W=e(V);u(W,`id`,`unverifiable`);var G=e(W,2);u(G,`id`,`secrets`);var K=e(G,2),q=e(i(K),2),J=e(i(q),2);u(J,`href`,`#secret-names`),o(),s(q),o(),s(K);var Y=e(K,2);u(Y,`id`,`secret-names`);var X=e(Y,5);u(X,`id`,`masked-hosts-and-review`);var Z=e(X,3);u(Z,`id`,`what-masking-covers`);var Q=e(Z),ee=e(i(Q),21);o(3),s(Q);var $=e(Q),te=e(i($),3);o(),s($),o(2),r((e,t,n,r,i,a)=>{u(f,`href`,e),u(b,`href`,t),u(x,`href`,n),u(L,`href`,r),u(ee,`href`,i),u(te,`href`,a)},[()=>m(`docs/configs#the-sandbox`),()=>m(`docs/security#secrets`),()=>m(`docs/resources#content`),()=>m(`docs/targets#the-target`),()=>m(`docs/security#secrets`),()=>m(`docs/lock`)]),l(t,c)},$$slots:{default:!0}})},$$slots:{default:!0}}),f()}export{b as t};