import{$ as e,G as t,J as n,K as r,X as i,Z as a,dt as o,ft as s,j as c,k as l,l as u,m as d,ot as f,st as p}from"./CkSeWg2M.js";import{t as m}from"./Cyt8LZpN.js";import{n as h}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as g}from"./k6TRNp0w.js";import{t as _}from"./BzaAmULn.js";var v=c(`<h2>The config</h2><p><strong>Why TypeScript for the config?</strong> Because the config needs loops, constants,
functions, and types, and inventing a DSL for those is how YAML grows a template
language. TypeScript has them, editors understand it, and the shipped recipes
are ordinary functions. The config only <em>describes</em>: it runs in a sandbox and
emits JSON. Zap evaluates it once, before it reads the machine; what executes is the plan
built from that JSON, and none of your TypeScript runs on the target.</p><p><strong>What runs the config? Can I use Node, Deno, or Bun?</strong> <code>fgro eval</code>, Gro's
runtime. Zap is a compiled Rust binary and can't run TypeScript itself, so <code>fgro</code> evaluates the config in a kernel sandbox that reads only the config's
project and the packages it links (<a>the sandbox</a>).
Each project pins one <code>fgro</code> build by hash in <code>zap.lock</code>. Node, Deno, and Bun
have no such sandbox, so Zap doesn't support them. Nothing runs on the target
but shell.</p><p><strong>Where are secrets stored?</strong> Nowhere Zap owns. They live in your environment
or an env file you keep out of version control, referenced with <code>zap.env('NAME')</code>, and
resolved when Zap acts. Resolved values are masked in every output, and the lock
file and last-run report hold a fixed token for each recognized secret
(<a>env.md</a>; list others with <code>zap.mask()</code>).</p><p><strong>What is <code>zap.lock</code> and should I commit it?</strong> It pins the <code>fgro</code> build that
evaluates the config, and fetched content (a <code>remote</code> file, a <code>build</code> source) to
the hash of the bytes you approved. Commit
it with <code>zap.ts</code>. It changes only when you run <code>zap update</code>, <code>zap lock</code>, or an <code>apply --wetrun</code> that has a tracked source to pin. <a>lock.md</a>.</p><h2>Running it</h2><p><strong>Why is the dry run the default?</strong> So the safe thing is the zero-effort thing,
and so a script, a CI job, or an assistant can't act by accident. Tools that
default to acting rely on an interactive prompt, which is exactly what gets
auto-approved. Here <code>--wetrun</code> is the act, and a wetrun with nothing reviewed
asks for the first characters of the plan's hash, which nothing can type before
the plan is on the screen.</p><p><strong>What does <code>--wetrun</code> refusing mean?</strong> A wetrun executes only the plan you
reviewed. If its fresh plan doesn't match the most recent preview on that host,
or the hash given to <code>--expect-plan</code>, it shows the plan, changes nothing, and
exits 2; running it again executes if nothing moved. On an interactive terminal
without <code>--expect-plan</code>, it asks instead: type the start of the plan's hash to
run it. <a>concepts.md</a>.</p><p><strong>Why did <code>zap plan</code> exit 0 when there are changes, but <code>zap apply</code> exit 2?</strong> <code>plan</code> reports; it doesn't judge. <code>apply</code> judges: 0 converged, 2 changes pending,
1 something couldn't be established. Use <code>apply</code> in a script that needs the
verdict. <a>cli.md</a>.</p><p><strong>What is <code>undetermined</code>?</strong> Zap couldn't read the resource and refuses to guess.
It is held out of the plan, reported with its reason, and the run exits 1. The
usual causes: a remote path using <code>~</code> with no <code>home</code> declared, a tracked <code>remote</code> file with no lock entry, a probe that failed or timed out, <code>sudo</code> that
wouldn't authenticate. Fix the cause and plan again; nothing carries over. <a>concepts.md</a>.</p><p><strong>Why does a <code>script</code> run on every apply?</strong> Its <code>check</code> fails on a converged
host. The <code>check</code> is the whole idempotency contract: make it exit 0 exactly
when the work is done. After a wetrun Zap runs the check again and reports <code>RESIDUAL</code> if it still fails.</p><p><strong>Why does <code>apply</code> write to <code>/var/lib/zap/pending/</code> on my host?</strong> Each marker
there is a restart or reload a service still owes, written before the change that
triggers it and cleared after. It is how a reload a failed run owed survives to
the next plan (<a>concepts.md</a>). The rest of what Zap leaves
on a target, beside what you declared, is listed in <a>install.md</a>.</p><h2>Scope</h2><p><strong>Does Zap need anything installed on the target?</strong> <code>sshd</code>, a POSIX shell with
coreutils or BusyBox, and <code>sudo</code>. No agent, no Python, no runtime. <a>targets.md</a> has the per-distro list.</p><p><strong>I removed a resource from the config. Why is it still on the machine?</strong> Zap
never removes what you stop declaring; it reports it as orphaned in <code>zap status</code>.
To remove something, declare the removal (a <code>script</code> whose <code>check</code> confirms it
is gone, or <code>sudo: false</code> on a user). This is the same posture as Ansible and
Puppet, and the opposite of Terraform and NixOS.</p><p><strong>Can one config manage several hosts?</strong> One target per config. For a few hosts,
one config per host (sharing modules), one env file per host, a shell loop. For a
fleet with parallel execution, Zap is the wrong tool; see <a>comparison.md</a>.</p><p><strong>Does Zap work on macOS, Arch, Fedora, Windows?</strong> No. Debian/Ubuntu and
Alpine. <code>pacman</code>, <code>brew</code>, and <code>launchd</code> parse in the schema but have no backend,
so their resources read undetermined. Running Zap <em>from</em> macOS against a Linux
host is unsupported: <code>fgro</code>'s sandbox needs Linux, so your side does too.</p><p><strong>Is Zap stable?</strong> No: pre-alpha, one maintainer, and the schema and CLI change
without compatibility layers. <a>stability.md</a> names the surfaces
whose breaks a release calls out. Read <a>security.md</a> before
pointing Zap at a machine you care about.</p><h2>Agents and alternatives</h2><p><strong>Can an AI agent run Zap?</strong> Yes, and it is designed for that: the default
command is read-only, the plan is a hash-named fact the agent can show you, the
wetrun executes only that plan, and <code>--json</code> streams typed events. Give the
agent <code>zap plan</code> and <code>zap apply</code> freely and keep <code>--wetrun</code> for the human, or
let it wetrun with <code>--expect-plan</code> set to the hash you approved.</p><p><strong>How is this different from a shell script with <code>if</code> guards?</strong> That script is
reaching toward what Zap declares: detection (skip what's done), idempotent
re-runs, a preview before acting, and a report after. Zap adds the parts a
script never grows: a refusal to guess when a read fails, a re-read after acting,
secrets masked everywhere, and a review bound to the act. <code>script</code> resources let
you keep the shell where it is the right tool.</p><p><strong>How is this different from Ansible / Terraform / NixOS / Kamal?</strong> <a>comparison.md</a>, with tables.</p>`,1);function y(c,y){p(y,!0);let b=h(`faq`);d(`1hnvmvd`,e=>{t(()=>{n.title=`FAQ — zap`})}),g(c,{get tome(){return b},children:(t,n)=>{_(t,{children:(t,n)=>{var c=v(),d=a(c);u(d,`id`,`the-config`);var f=e(d,2),p=e(i(f),6);o(5),s(f);var h=e(f),g=e(i(h),4);o(3),s(h);var _=e(h),y=e(i(_),16);o(),s(_);var b=e(_);u(b,`id`,`running-it`);var x=e(b,2),S=e(i(x),6);o(),s(x);var C=e(x),w=e(i(C),8);o(),s(C);var T=e(C),E=e(i(T),10);o(),s(T);var D=e(T,2),O=e(i(D),2),k=e(O,2);o(),s(D);var A=e(D);u(A,`id`,`scope`);var j=e(A),M=e(i(j),6);o(),s(j);var N=e(j,2),P=e(i(N),2);o(),s(N);var F=e(N,2),I=e(i(F),2),L=e(I,2);o(),s(F);var R=e(F);u(R,`id`,`agents-and-alternatives`);var z=e(R,3),B=e(i(z),2);o(),s(z),r((e,t,n,r,i,a,o,s,c,l,d,f,m)=>{u(p,`href`,e),u(g,`href`,t),u(y,`href`,n),u(S,`href`,r),u(w,`href`,i),u(E,`href`,a),u(O,`href`,o),u(k,`href`,s),u(M,`href`,c),u(P,`href`,l),u(I,`href`,d),u(L,`href`,f),u(B,`href`,m)},[()=>m(`docs/configs#the-sandbox`),()=>m(`docs/env#secrets`),()=>m(`docs/lock`),()=>m(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>m(`docs/cli#exit-codes-all-commands`),()=>m(`docs/concepts#detection`),()=>m(`docs/concepts#triggers`),()=>m(`docs/install#uninstall`),()=>m(`docs/targets#what-the-target-needs`),()=>m(`docs/comparison`),()=>m(`docs/stability`),()=>m(`docs/security`),()=>m(`docs/comparison`)]),l(t,c)},$$slots:{default:!0}})},$$slots:{default:!0}}),f()}export{y as t};