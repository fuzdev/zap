import{$ as e,G as t,J as ee,K as te,X as n,Z as ne,dt as re,ft as r,j as i,k as ie,l as a,m as o,ot as s,st as ae}from"./CkSeWg2M.js";import{t as c}from"./Cyt8LZpN.js";import{n as l}from"./BbCw5KVU.js";import"./BPVwp-J3.js";import{t as oe}from"./k6TRNp0w.js";import{t as u}from"./CtsBFaJL.js";var se=i(`<p> <a>concepts.md</a>.</p><p><strong>Absent</strong> — a detection verdict: the resource isn't present; the planner
creates it. <a>concepts.md</a></p><p><strong>Additive</strong> — a declared list where each entry must be present and an entry
added by hand is neither detected nor removed: firewall allow rules, <code>pg_hba</code> <a>concepts.md</a></p><p><strong>Apply</strong> — <code>zap apply</code>: a dry run of the plan by default; with <code>--wetrun</code>, the
command that changes the machine. <a>cli.md</a></p><p><strong>Authoritative</strong> — a field made exactly the declared value; anything added by
hand is removed, not merged. One of three field classes, beside additive and
unset. <a>concepts.md</a></p><p><strong>Batch</strong> <a>detection.md</a></p><p><strong>Bootstrap user</strong> — <code>target.bootstrap_user</code> <code>--bootstrap</code> connects as for a first provisioning run before SSH hardening
locks it out. <a>targets.md</a></p><p><strong>Build</strong> — the <code>build</code> resource: fetch a source archive, verify and pin it,
build it, record its provenance in a sidecar. <a>resources.md</a></p><p><strong>Changeset</strong> — the resources the plan will create or update, with their steps.
What <code>plan_hash</code> names. <a>concepts.md</a></p><p><strong>Converged</strong> <a>concepts.md</a></p><p><strong>Convergent</strong> <a>concepts.md</a></p><p><strong>Declaration</strong> — the JSON a config evaluates to: the target plus every
resource. A pure function of <code>zap.ts</code> and the files it reads. <a>configs.md</a></p><p><strong>Deploy</strong> — <code>zap deploy</code> <code>releases/&lt;version></code> plus a <code>current</code> symlink, restart, health-check, roll back
on failure. The one imperative command. <a>deploy.md</a></p><p><strong>Depth</strong> <a>detection.md</a></p><p><strong>Drift</strong> — the gap between the live machine and the declaration. Found by
reading, every run; never tracked. <a>concepts.md</a></p><p><strong>Drifted</strong> — a detection verdict: present but wrong, carrying what was
observed; the planner updates it. <a>concepts.md</a></p><p><strong>Dry run</strong> — <code>apply</code> or <code>deploy</code> without <code>--wetrun</code> <a>concepts.md</a></p><p><strong>Elevated</strong> — a detection privilege: root over SSH; on a local target, the
operator first and <code>sudo</code> <a>detection.md</a></p><p><strong>Env file</strong> — a file of <code>NAME=VALUE</code> lines loaded with <code>--env-file</code>, the source of
reference values alongside the environment. <a>env.md</a></p><p><strong>Extract sentinel</strong> — the <code>.zap_remote_hash</code> file an extracted <code>remote</code> file
leaves in its destination, recording a digest of the tarball pin and the extract
form. <a>lock.md</a></p><p><strong>Gates</strong> — the machine-free checks every command runs on the declaration:
secrets and structure. <a>configs.md</a></p><p><strong>Held</strong> — what happens to an undetermined resource: left out of the plan,
reported, exit 1. A change that depends on a held resource, or would trigger a
held service, is held behind it. <a>concepts.md</a></p><p><strong>Imperative</strong> — a resource or command that always runs because there is no
stable state to converge to: <code>pipeline</code>, <code>deploy</code> <a>concepts.md</a></p><p><strong>Lane</strong> <a>detection.md</a></p><p><strong>Last-run report</strong> — what the most recent detection pass on a host read, kept
under <code>~/.zap</code> and rendered by <code>zap status</code>; a preview's report holds the plan a
wetrun binds to. <a>detection.md</a></p><p><strong>Lock standing</strong> — a tracked pin's classification against the config: current,
missing, stale, unverifiable, or orphan. <a>lock.md</a></p><p><strong>Login</strong> <a>detection.md</a></p><p><strong>Mask</strong> — removing a resolved secret's value from every output. <code>zap.mask()</code> <code>zap.unmask()</code> say so for a reference the rule reads wrongly. <a>env.md</a></p><p><strong>Operator</strong> — you: the person (or agent) running Zap, whose environment
supplies reference values and whose SSH keys reach the target.</p><p><strong>Orphan</strong> — a last-run resource, or a lock entry, that the config no longer
declares. Warn-only. <a>lock.md</a></p><p><strong>Pass</strong> — one detection of every declared resource against the target: every
read batched, every resource read live. <a>detection.md</a></p><p><strong>Pending trigger</strong> — a marker under <code>/var/lib/zap/pending/</code> on the target
recording a restart or reload a run owes a service. <a>concepts.md</a></p><p><strong>Pin</strong> — the blake3 of fetched bytes, declared in the config (vendored) or
recorded in <code>zap.lock</code> (tracked). <a>lock.md</a></p><p><strong>Plan</strong> — the changeset for one run against one target, and the command that
renders it. <a>concepts.md</a></p><p><strong><code>plan_hash</code></strong> <code>--expect-plan</code>. It covers the changes, the machine they are for, what each
reference resolves to (a secret only as the fact), and the text Zap's own steps
run. <a>concepts.md</a></p><p><strong>Preflight</strong> — the convergence pass <code>deploy --wetrun</code> runs before shipping;
drift or an unreadable resource refuses the release. <a>deploy.md</a></p><p><strong>Preview</strong> — a pass that rendered a plan and executed nothing: <code>zap plan</code>, a
dry <code>zap apply</code>, a refused wetrun. Its plan is the one a wetrun binds to by
default. <code>zap deploy</code> keeps its own, the <strong>deploy preview</strong> <a>deploy.md</a> <a>concepts.md</a></p><p><strong>Provenance sidecar</strong> — the <code>&lt;output>.zap-build</code> file recording a digest of the
source pin a build came from and how it was built. <a>lock.md</a></p><p><strong>Recipe</strong> <a>recipes.md</a></p><p><strong>Reference</strong> — <code>zap.env('NAME')</code>: a stand-in for an operator-environment
value, inert in the declaration, resolved when Zap acts, shown as <code></code> <a>env.md</a></p><p><strong>Refused</strong> <a>concepts.md</a></p><p><strong>Residual</strong> — a resource that still doesn't read converged after a wetrun's
changes ran. Exit 1. <a>concepts.md</a></p><p><strong>Resource</strong> — one typed unit of desired state with a stable <code>id</code> <a>resources.md</a></p><p><strong>Reviewed plan</strong> <code>--expect-plan &lt;hash></code> <a>concepts.md</a></p><p><strong>Root</strong> <a>detection.md</a></p><p><strong>Target</strong> — where a config acts: <code>local: true</code>, or a host over SSH, with its
package and service managers. <a>targets.md</a></p><p><strong>Template kind</strong> — the form a <code>template</code> variable's value is held to
(<code>hostname</code>, <code>port</code>, <code>path</code> <code>hostname</code> in an nginx <code>server_name</code> <a>resources.md</a></p><p><strong>Toolchain pin</strong> — the <code>fgro</code> <code>zap.lock</code> by <code>zap lock</code> <a>lock.md</a></p><p><strong>Tracked</strong> — a <code>remote</code> file, <code>build</code> source, or <code>apt_repo</code> signing key with no
pin in the config; the pin lives in <code>zap.lock</code>. <a>lock.md</a></p><p><strong>Trigger</strong> — a <code>file</code>'s <code>triggers</code>, or a <code>service</code>'s <code>restart_on</code> <code>reload_on</code>: a change in the source promotes the service to a restart or
reload. <a>concepts.md</a></p><p><strong>Two-tier privilege escalation</strong> <code>sudo</code>; on a local target file operations try natively and escalate only when
denied, and over SSH they run under <code>sudo</code> <a>targets.md</a></p><p><strong>Unbindable</strong> — a plan whose host, connecting user, or deploy health domain
resolves through a masked reference: it has no <code>plan_hash</code>, so no wetrun can
bind to it. <a>env.md</a></p><p><strong>Undetermined</strong> — a detection verdict: Zap couldn't read the resource and
won't guess. Held. <a>concepts.md</a></p><p><strong>Unset</strong> — a field the config leaves out: unmanaged, neither set nor
reverted. <a>concepts.md</a></p><p><strong>Unverifiable</strong> — a comparing pass whose desired side depended on an unset
reference. Exit 1. <a>env.md</a></p><p><strong>Vendored</strong> — a <code>remote</code> file, <code>build</code> source, or <code>apt_repo</code> signing key
pinned by a <code>blake3</code> in the config itself (an <code>apt_repo</code>'s <code>key_blake3</code>). No
lock entry. <a>lock.md</a></p><p><strong>Verdict</strong> — detection's answer per resource: converged, drifted, absent, or
undetermined. <a>concepts.md</a></p><p><strong>Wetrun</strong> — <code>--wetrun</code>: the flag that makes <code>apply</code> or <code>deploy</code> <a>concepts.md</a></p><p><strong>Withheld</strong> — a tracked pin that isn't current, dropped before detection by
the read-only commands so its resource holds. <a>lock.md</a></p><p><strong><code>zap.lock</code></strong> — the pin ledger next to <code>zap.ts</code> <a>lock.md</a></p><p><strong><code>~/.zap</code></strong> — the operator-side state directory (or <code>$ZAP_HOME</code> <code>~/.zap/bin</code> <a>lock.md</a></p>`,1);function d(i,d){ae(d,!0);let ce=l(`glossary`);o(`16asznf`,e=>{t(()=>{ee.title=`Glossary — zap`})}),oe(i,{get tome(){return ce},children:(t,ee)=>{u(t,{children:(t,ee)=>{var i=se(),o=ne(i),s=n(o);s.nodeValue=`One line per term, with where it's explained. The model itself is in
`;var ae=e(s);re(),r(o);var l=e(o),oe=e(n(l),2);r(l);var u=e(l),d=e(n(u),3);d.nodeValue=`
rules, a user's groups. `;var ce=e(d);r(u);var f=e(u),le=e(n(f),6);r(f);var p=e(f),ue=e(n(p),2);r(p);var m=e(p),h=e(n(m));h.nodeValue=` — one shell script per lane carrying every detection read
of a pass, delivered on stdin, run once per pass.
`;var de=e(h);r(m);var g=e(m),_=e(n(g),3);_.nodeValue=`, the alternate account
`;var fe=e(_,3);r(g);var v=e(g),pe=e(n(v),4);r(v);var y=e(v),me=e(n(y),4);r(y);var b=e(y),x=e(n(b));x.nodeValue=` — a detection verdict: the desired state is already present;
nothing to do. Also the state of a machine whose every resource reads so.
`;var he=e(x);r(b);var S=e(b),C=e(n(S));C.nodeValue=` — the control model: read the current state, diff it against the
declared state, change only the difference. Re-running is always safe.
`;var ge=e(C);r(S);var w=e(S),_e=e(n(w),4);r(w);var T=e(w),E=e(n(T),3);E.nodeValue=`: ship a versioned release to a remote host as
`;var ve=e(E,5);r(T);var D=e(T),O=e(n(D));O.nodeValue=` — how much detection reads for a kind: existence, attributes, or
content. Matches the kind's execution idempotency.
`;var ye=e(O);r(D);var k=e(D),be=e(n(k),2);r(k);var A=e(k),xe=e(n(A),2);r(A);var j=e(A),Se=e(n(j),7);Se.nodeValue=`: reads the target, renders
the plan, changes nothing on it.
`;var Ce=e(Se);r(j);var M=e(j),we=e(n(M),3);we.nodeValue=` for a read that failed.
`;var Te=e(we);r(M);var N=e(M),Ee=e(n(N),6);r(N);var P=e(N),De=e(n(P),6);r(P);var F=e(P),Oe=e(n(F),2);r(F);var I=e(F),ke=e(n(I),2);r(I);var L=e(I),R=e(n(L),5);R.nodeValue=`.
`;var Ae=e(R);r(L);var z=e(L),B=e(n(z));B.nodeValue=` — one of a pass's batches, named for what it runs as: login, or root.
A lane is not a privilege: the root lane carries both the root and the elevated
reads.
`;var je=e(B);r(z);var V=e(z),Me=e(n(V),6);r(V);var H=e(V),Ne=e(n(H),2);r(H);var U=e(H),W=e(n(U));W.nodeValue=` — a detection privilege: the connecting user, unprivileged.
`;var Pe=e(W);r(U);var G=e(U),K=e(n(G),3);K.nodeValue=` /
`;var Fe=e(K,3);r(G);var q=e(G,2),Ie=e(n(q),2);r(q);var J=e(q),Le=e(n(J),2);r(J);var Y=e(J),Re=e(n(Y),4);r(Y);var X=e(Y),ze=e(n(X),4);r(X);var Z=e(X),Be=e(n(Z),2);r(Z);var Q=e(Z),Ve=e(n(Q));Ve.nodeValue=` — the blake3 that names a plan for review and for
`;var He=e(Ve,3);r(Q);var Ue=e(Q),We=e(n(Ue),4);r(Ue);var Ge=e(Ue),Ke=e(n(Ge),9);Ke.nodeValue=`
(`;var qe=e(Ke),Je=e(qe);Je.nodeValue=`).
`;var Ye=e(Je);r(Ge);var Xe=e(Ge),Ze=e(n(Xe),4);r(Xe);var Qe=e(Xe),$e=e(n(Qe));$e.nodeValue=` — a shipped pure function returning a config fragment.
`;var et=e($e);r(Qe);var tt=e(Qe),nt=e(n(tt),4);nt.textContent=`{env:NAME}`;var rt=e(nt);rt.nodeValue=`.
`;var it=e(rt);r(tt);var at=e(tt),ot=e(n(at));ot.nodeValue=` — a wetrun that didn't execute because its plan wasn't the reviewed
one, or, asked on a terminal, wasn't confirmed (declined). Exit 2; the plan is
rendered and becomes the preview.
`;var st=e(ot);r(at);var ct=e(at),lt=e(n(ct),2);r(ct);var ut=e(ct),dt=e(n(ut),3);dt.nodeValue=`.
`;var ft=e(dt);r(ut);var pt=e(ut),mt=e(n(pt));mt.nodeValue=` — the plan a wetrun must match to execute: the one named by
`;var ht=e(mt,2);ht.nodeValue=`, or the one in the host's last-run report when that pass
was a preview, recorded when Zap printed it, whether or not anyone read it, and
withdrawn when its output couldn't be written.
`;var gt=e(ht);r(pt);var _t=e(pt),vt=e(n(_t));vt.nodeValue=` — a detection privilege: root on every connection.
`;var yt=e(vt);r(_t);var bt=e(_t),xt=e(n(bt),4);r(bt);var St=e(bt),Ct=e(n(St),9);Ct.nodeValue=`, …), checked on its whole rendered value: a
`;var wt=e(Ct,4);wt.nodeValue=` can't end the directive.
`;var Tt=e(wt);r(St);var Et=e(St),Dt=e(n(Et),3);Dt.nodeValue=` build a config is evaluated with, recorded in
`;var Ot=e(Dt,4);Ot.nodeValue=`; a missing or mismatched pin refuses.
`;var kt=e(Ot);r(Et);var At=e(Et),jt=e(n(At),10);r(At);var Mt=e(At),Nt=e(n(Mt),9);Nt.nodeValue=` /
`;var Pt=e(Nt,3);r(Mt);var Ft=e(Mt),It=e(n(Ft));It.nodeValue=` — privileged commands carry an explicit
`;var Lt=e(It,4);Lt.nodeValue=`.
`;var Rt=e(Lt);r(Ft);var zt=e(Ft),Bt=e(n(zt),4);r(zt);var Vt=e(zt),Ht=e(n(Vt),2);r(Vt);var Ut=e(Vt),Wt=e(n(Ut),2);r(Ut);var Gt=e(Ut),Kt=e(n(Gt),2);r(Gt);var $=e(Gt),qt=e(n($),14);r($);var Jt=e($),Yt=e(n(Jt),2);r(Jt);var Xt=e(Jt),Zt=e(n(Xt),7);Zt.nodeValue=` act. Zap's
word for "not a dry run", chosen to be hard to type by accident.
`;var Qt=e(Zt);r(Xt);var $t=e(Xt),en=e(n($t),2);r($t);var tn=e($t),nn=e(n(tn),3);nn.nodeValue=`, committed with it.
`;var rn=e(nn);r(tn);var an=e(tn),on=e(n(an),3);on.nodeValue=`): caches,
last-run reports, deploy previews, SSH sockets; the installed binary stays in
`;var sn=e(on,2);sn.nodeValue=`. Never part of the plan.
`;var cn=e(sn);r(an),te((e,t,ee,te,n,ne,re,r,i,ie,o,s,c,l,u,se,d,f,p,m,h,g,_,v,y,b,x,S,C,w,T,E,D,O,k,A,j,Se,M,we,N,P,F,I,L,R,z,B,V,H,U,W,G,K,q,J,Y,X,Z,Q,Ve)=>{a(ae,`href`,e),a(oe,`href`,t),a(ce,`href`,ee),a(le,`href`,te),a(ue,`href`,n),a(de,`href`,ne),a(fe,`href`,re),a(pe,`href`,r),a(me,`href`,i),a(he,`href`,ie),a(ge,`href`,o),a(_e,`href`,s),a(ve,`href`,c),a(ye,`href`,l),a(be,`href`,u),a(xe,`href`,se),a(Ce,`href`,d),a(Te,`href`,f),a(Ee,`href`,p),a(De,`href`,m),a(Oe,`href`,h),a(ke,`href`,g),a(Ae,`href`,_),a(je,`href`,v),a(Me,`href`,y),a(Ne,`href`,b),a(Pe,`href`,x),a(Fe,`href`,S),a(Ie,`href`,C),a(Le,`href`,w),a(Re,`href`,T),a(ze,`href`,E),a(Be,`href`,D),a(He,`href`,O),a(We,`href`,k),a(qe,`href`,A),a(Ye,`href`,j),a(Ze,`href`,Se),a(et,`href`,M),a(it,`href`,we),a(st,`href`,N),a(lt,`href`,P),a(ft,`href`,F),a(gt,`href`,I),a(yt,`href`,L),a(xt,`href`,R),a(Tt,`href`,z),a(kt,`href`,B),a(jt,`href`,V),a(Pt,`href`,H),a(Rt,`href`,U),a(Bt,`href`,W),a(Ht,`href`,G),a(Wt,`href`,K),a(Kt,`href`,q),a(qt,`href`,J),a(Yt,`href`,Y),a(Qt,`href`,X),a(en,`href`,Z),a(rn,`href`,Q),a(cn,`href`,Ve)},[()=>c(`docs/concepts`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#convergence`),()=>c(`docs/cli#zap-apply`),()=>c(`docs/concepts#convergence`),()=>c(`docs/detection#batches`),()=>c(`docs/targets#the-bootstrap-user`),()=>c(`docs/resources#build`),()=>c(`docs/concepts#the-plan`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#convergence`),()=>c(`docs/configs#the-sandbox`),()=>c(`docs/deploy`),()=>c(`docs/detection#per-resource-depth`),()=>c(`docs/concepts#convergence`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#dry-run-and-wetrun`),()=>c(`docs/detection#privilege`),()=>c(`docs/env#the-env-file`),()=>c(`docs/lock#what-detection-compares`),()=>c(`docs/configs#what-the-gates-reject`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#convergence`),()=>c(`docs/detection#privilege`),()=>c(`docs/detection#the-last-run-report`),()=>c(`docs/lock#standing`),()=>c(`docs/detection#privilege`),()=>c(`docs/env#secrets`),()=>c(`docs/lock#standing`),()=>c(`docs/detection`),()=>c(`docs/concepts#triggers`),()=>c(`docs/lock`),()=>c(`docs/concepts#the-plan`),()=>c(`docs/concepts#the-plan`),()=>c(`docs/deploy#preflight`),()=>c(`docs/deploy#binding-a-wetrun-to-a-reviewed-plan`),()=>c(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>c(`docs/lock#what-detection-compares`),()=>c(`docs/recipes`),()=>c(`docs/env#references`),()=>c(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>c(`docs/concepts#apply-asserts-convergence`),()=>c(`docs/resources`),()=>c(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>c(`docs/detection#privilege`),()=>c(`docs/targets`),()=>c(`docs/resources#content`),()=>c(`docs/lock#the-toolchain-pin`),()=>c(`docs/lock`),()=>c(`docs/concepts#triggers`),()=>c(`docs/targets#two-tier-privilege-escalation`),()=>c(`docs/env#masked-hosts-and-review`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#convergence`),()=>c(`docs/env#unverifiable`),()=>c(`docs/lock#two-kinds-of-fetched-content`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#dry-run-and-wetrun`),()=>c(`docs/lock#who-writes-who-reads`),()=>c(`docs/lock`),()=>c(`docs/lock#on-disk-state`)]),ie(t,i)},$$slots:{default:!0}})},$$slots:{default:!0}}),s()}export{d as t};