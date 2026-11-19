import{K as e,Q as t,Y as n,Z as r,ct as i,et as a,j as o,k as s,l as c,lt as l,m as u,mt as d,pt as f,q as p}from"./DGWDGHf_.js";import{t as m}from"./hWJyV7ZK.js";import{t as h}from"./xlPESoVd.js";import{t as g}from"./B0EoXBDb.js";import{n as _}from"./BkOGAUkd.js";import"./CMLJYHjj.js";var v=o(`<h2>The config</h2><p><strong>Why TypeScript for the config?</strong> Because the config needs loops, constants,
functions, and types, and inventing a DSL for those is how YAML grows a template
language. TypeScript has them, editors understand it, and the shipped recipes
are ordinary functions. The config only <em>describes</em>: it runs in a sandbox and
emits JSON. Zap evaluates it once, before it reads the machine; what executes is the plan
built from that JSON, and none of your TypeScript runs on the target.</p><p><strong>What runs the config? Can I use Node, Deno, or Bun?</strong> <code>fgro eval</code> <code>fgro</code> evaluates the config in a kernel sandbox that reads only the config's
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
it with <code>zap.ts</code>. It changes only when you run <code>zap update</code>, <code>zap lock</code> <code>apply --wetrun</code> <a>lock.md</a>.</p><h2>Running it</h2><p><strong>Why is the dry run the default?</strong> So the safe thing is the zero-effort thing,
and so a script, a CI job, or an assistant can't act by accident. Tools that
default to acting rely on an interactive prompt, which is exactly what gets
auto-approved. Here <code>--wetrun</code> is the act, and a wetrun with nothing reviewed
asks for the first characters of the plan's hash, which nothing can type before
the plan is on the screen.</p><p><strong>What does <code>--wetrun</code> refusing mean?</strong> A wetrun executes only the plan you
reviewed. If its fresh plan doesn't match the most recent preview on that host,
or the hash given to <code>--expect-plan</code>, it shows the plan, changes nothing, and
exits 2; running it again executes if nothing moved. On an interactive terminal
without <code>--expect-plan</code> <a>concepts.md</a>.</p><p><strong>Why did <code>zap plan</code> exit 0 when there are changes, but <code>zap apply</code> exit 2?</strong> <code>plan</code> reports; it doesn't judge. <code>apply</code> judges: 0 converged, 2 changes pending,
1 something couldn't be established. Use <code>apply</code> in a script that needs the
verdict. <a>cli.md</a>.</p><p><strong>What is <code>undetermined</code>?</strong> Zap couldn't read the resource and refuses to guess.
It is held out of the plan, reported with its reason, and the run exits 1. The
usual causes: a remote path using <code>~</code> with no <code>home</code> <code>remote</code> file with no lock entry, a probe that failed or timed out, <code>sudo</code> <a>concepts.md</a>.</p><p><strong>Why does a <code>script</code> run on every apply?</strong> Its <code>check</code> fails on a converged
host. The <code>check</code> <code>RESIDUAL</code> if it still fails.</p><p><strong>Why does <code>apply</code> write to <code>/var/lib/zap/pending/</code> on my host?</strong> Each marker
there is a restart or reload a service still owes, written before the change that
triggers it and cleared after. It is how a reload a failed run owed survives to
the next plan (<a>concepts.md</a> <a>install.md</a>.</p><h2>Scope</h2><p><strong>Does Zap need anything installed on the target?</strong> <code>sshd</code>, a POSIX shell with
coreutils or BusyBox, and <code>sudo</code> <a>targets.md</a> has the per-distro list.</p><p><strong>I removed a resource from the config. Why is it still on the machine?</strong> Zap
never removes what you stop declaring; it reports it as orphaned in <code>zap status</code>.
To remove something, declare the removal (a <code>script</code> whose <code>check</code> confirms it
is gone, or <code>sudo: false</code> on a user). This is the same posture as Ansible and
Puppet, and the opposite of Terraform and NixOS.</p><p><strong>Can one config manage several hosts?</strong> <a>comparison.md</a>.</p><p><strong>Does Zap work on macOS, Arch, Fedora, Windows?</strong> No. Debian/Ubuntu and
Alpine. <code>pacman</code>, <code>brew</code>, and <code>launchd</code> parse in the schema but have no backend,
so their resources read undetermined, and the TypeScript types leave them out. Running Zap <em>from</em> macOS against a Linux
host is unsupported: <code>fgro</code>'s sandbox needs Linux, so your side does too.</p><p><strong>Is Zap stable?</strong> No: pre-alpha, one maintainer, and the schema and CLI change
without compatibility layers. <a>stability.md</a> names the surfaces
whose breaks a release calls out. Read <a>security.md</a> before
pointing Zap at a machine you care about.</p><h2>Agents and alternatives</h2><p><strong>Can an AI agent run Zap?</strong> Yes, and it is designed for that: the default
command is read-only, the plan is a hash-named fact the agent can show you, a
wetrun given that hash executes only that plan, and <code>--json</code> streams typed
events. Give the agent <code>zap plan</code> and <code>zap apply</code> freely and keep <code>--wetrun</code> for
the human, or let it wetrun with <code>--expect-plan</code> set to the hash you approved.
Without the flag, a wetrun binds to the last preview Zap printed on that host,
whether or not anyone read it: a preview an agent cut short with <code>head</code> still
binds once the pipe took it whole, and the hash is its last line.</p><p><strong>How is this different from a shell script with <code>if</code> guards?</strong> That script is
reaching toward what Zap declares: detection (skip what's done), idempotent
re-runs, a preview before acting, and a report after. Zap adds the parts a
script never grows: a refusal to guess when a read fails, a re-read after acting,
secrets masked everywhere, and a review bound to the act. <code>script</code> resources let
you keep the shell where it is the right tool.</p><p><strong>How is this different from Ansible / Terraform / NixOS / Kamal?</strong> <a>comparison.md</a>, with tables.</p>`,1);function y(o,y){l(y,!0);let b=_(`faq`);u(`1hnvmvd`,t=>{e(()=>{n.title=`FAQ — zap`})}),g(o,{get tome(){return b},children:(e,n)=>{h(e,{children:(e,n)=>{var i=v(),o=t(i);c(o,`id`,`the-config`);var l=a(o,2),u=a(r(l),3);u.nodeValue=`, Gro's
runtime. Zap is a compiled Rust binary and can't run TypeScript itself, so
`;var h=a(u,3);f(5),d(l);var g=a(l),_=a(r(g),4);f(3),d(g);var y=a(g),b=a(r(y),13);b.nodeValue=`, or an
`;var x=a(b,2);x.nodeValue=` that has a tracked source to pin.
`;var S=a(x);f(),d(y);var C=a(y);c(C,`id`,`running-it`);var w=a(C,2),T=a(r(w),5);T.nodeValue=`, it asks instead: type the start of the plan's hash to
run it.
`;var E=a(T);f(),d(w);var D=a(w),O=a(r(D),1,!0);O.nodeValue=`
`;var k=a(O,7);f(),d(D);var A=a(D),j=a(r(A),5);j.nodeValue=` declared, a tracked
`;var M=a(j,4);M.nodeValue=` that
wouldn't authenticate. Fix the cause and plan again; nothing carries over.
`;var N=a(M);f(),d(A);var P=a(A),F=a(r(P),5);F.nodeValue=` is the whole idempotency contract: make it exit 0 exactly
when the work is done. After a wetrun Zap runs the check again and reports
`,f(2),d(P);var I=a(P),L=a(r(I),2),R=a(L);R.nodeValue=`). The rest of what Zap leaves
on a target, beside what you declared, is listed in
`;var z=a(R);f(),d(I);var B=a(I);c(B,`id`,`scope`);var V=a(B),H=a(r(V),5);H.nodeValue=`. No agent, no Python, no runtime.
`;var U=a(H);f(),d(V);var W=a(V,2),G=a(r(W));G.nodeValue=` One target per config. For a few hosts,
one config per host (sharing modules), one env file per host, a shell loop. For a
fleet with parallel execution, Zap is the wrong tool; see
`;var K=a(G);f(),d(W);var q=a(W,2),J=a(r(q),2),Y=a(J,2);f(),d(q);var X=a(q);c(X,`id`,`agents-and-alternatives`);var Z=a(X,3),Q=a(r(Z),1,!0);Q.nodeValue=`
`;var $=a(Q);f(),d(Z),p((e,t,n,r,i,a,o,s,l,u,d,f,p)=>{c(h,`href`,e),c(_,`href`,t),c(S,`href`,n),c(E,`href`,r),c(k,`href`,i),c(N,`href`,a),c(L,`href`,o),c(z,`href`,s),c(U,`href`,l),c(K,`href`,u),c(J,`href`,d),c(Y,`href`,f),c($,`href`,p)},[()=>m(`docs/configs#the-sandbox`),()=>m(`docs/env#secrets`),()=>m(`docs/lock`),()=>m(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>m(`docs/cli#exit-codes-all-commands`),()=>m(`docs/concepts#detection`),()=>m(`docs/concepts#triggers`),()=>m(`docs/install#uninstall`),()=>m(`docs/targets#what-the-target-needs`),()=>m(`docs/comparison`),()=>m(`docs/stability`),()=>m(`docs/security`),()=>m(`docs/comparison`)]),s(e,i)},$$slots:{default:!0}})},$$slots:{default:!0}}),i()}export{y as t};