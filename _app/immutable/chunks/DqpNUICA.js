import{K as e,Q as ee,Y as te,Z as t,ct as n,et as r,j as i,k as ne,l as a,lt as o,m as re,mt as s,pt as ie,q as ae}from"./DGWDGHf_.js";import{t as c}from"./hWJyV7ZK.js";import{t as l}from"./xlPESoVd.js";import{t as oe}from"./B0EoXBDb.js";import{n as u}from"./BkOGAUkd.js";import"./CMLJYHjj.js";var se=i(`<p> <a>concepts.md</a>.</p><p><strong>Absent</strong> — a detection verdict: the resource isn't present; the planner
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
the read-only commands so its resource holds. <a>lock.md</a></p><p><strong><code>zap.lock</code></strong> — the pin ledger next to <code>zap.ts</code> <a>lock.md</a></p><p><strong><code>~/.zap</code></strong> — the operator-side state directory (or <code>$ZAP_HOME</code> <code>~/.zap/bin</code> <a>lock.md</a></p>`,1);function d(i,d){o(d,!0);let ce=u(`glossary`);re(`16asznf`,ee=>{e(()=>{te.title=`Glossary — zap`})}),oe(i,{get tome(){return ce},children:(e,te)=>{l(e,{children:(e,te)=>{var n=se(),i=ee(n),o=t(i);o.nodeValue=`One line per term, with where it's explained. The model itself is in
`;var re=r(o);ie(),s(i);var l=r(i),oe=r(t(l),2);s(l);var u=r(l),d=r(t(u),3);d.nodeValue=`
rules, a user's groups. `;var ce=r(d);s(u);var f=r(u),le=r(t(f),6);s(f);var p=r(f),ue=r(t(p),2);s(p);var m=r(p),h=r(t(m));h.nodeValue=` — one shell script per lane carrying every detection read
of a pass, delivered on stdin, run once per pass.
`;var de=r(h);s(m);var g=r(m),_=r(t(g),3);_.nodeValue=`, the alternate account
`;var fe=r(_,3);s(g);var v=r(g),pe=r(t(v),4);s(v);var y=r(v),me=r(t(y),4);s(y);var b=r(y),he=r(t(b));he.nodeValue=` — a detection verdict: the desired state is already present;
nothing to do. Also the state of a machine whose every resource reads so.
`;var ge=r(he);s(b);var x=r(b),S=r(t(x));S.nodeValue=` — the control model: read the current state, diff it against the
declared state, change only the difference. Re-running is always safe.
`;var _e=r(S);s(x);var C=r(x),ve=r(t(C),4);s(C);var w=r(C),T=r(t(w),3);T.nodeValue=`: ship a versioned release to a remote host as
`;var ye=r(T,5);s(w);var E=r(w),D=r(t(E));D.nodeValue=` — how much detection reads for a kind: existence, attributes, or
content. Matches the kind's execution idempotency.
`;var be=r(D);s(E);var O=r(E),xe=r(t(O),2);s(O);var k=r(O),Se=r(t(k),2);s(k);var A=r(k),Ce=r(t(A),7);Ce.nodeValue=`: reads the target, renders
the plan, changes nothing on it.
`;var we=r(Ce);s(A);var j=r(A),Te=r(t(j),3);Te.nodeValue=` for a read that failed.
`;var Ee=r(Te);s(j);var M=r(j),De=r(t(M),6);s(M);var N=r(M),Oe=r(t(N),6);s(N);var P=r(N),ke=r(t(P),2);s(P);var F=r(P),Ae=r(t(F),2);s(F);var I=r(F),L=r(t(I),5);L.nodeValue=`.
`;var je=r(L);s(I);var R=r(I),z=r(t(R));z.nodeValue=` — one of a pass's batches, named for what it runs as: login, or root.
A lane is not a privilege: the root lane carries both the root and the elevated
reads.
`;var Me=r(z);s(R);var B=r(R),Ne=r(t(B),6);s(B);var V=r(B),Pe=r(t(V),2);s(V);var H=r(V),U=r(t(H));U.nodeValue=` — a detection privilege: the connecting user, unprivileged.
`;var Fe=r(U);s(H);var W=r(H),G=r(t(W),3);G.nodeValue=` /
`;var Ie=r(G,3);s(W);var K=r(W,2),Le=r(t(K),2);s(K);var q=r(K),Re=r(t(q),2);s(q);var J=r(q),ze=r(t(J),4);s(J);var Y=r(J),Be=r(t(Y),4);s(Y);var X=r(Y),Ve=r(t(X),2);s(X);var Z=r(X),He=r(t(Z));He.nodeValue=` — the blake3 that names a plan for review and for
`;var Ue=r(He,3);s(Z);var We=r(Z),Ge=r(t(We),4);s(We);var Ke=r(We),qe=r(t(Ke),9);qe.nodeValue=`
(`;var Je=r(qe),Ye=r(Je);Ye.nodeValue=`).
`;var Xe=r(Ye);s(Ke);var Ze=r(Ke),Qe=r(t(Ze),4);s(Ze);var $e=r(Ze),et=r(t($e));et.nodeValue=` — a shipped pure function returning a config fragment.
`;var tt=r(et);s($e);var nt=r($e),rt=r(t(nt),4);rt.textContent=`{env:NAME}`;var it=r(rt);it.nodeValue=`.
`;var at=r(it);s(nt);var ot=r(nt),st=r(t(ot));st.nodeValue=` — a wetrun that didn't execute because its plan wasn't the reviewed
one, or, asked on a terminal, wasn't confirmed (declined). Exit 2; the plan is
rendered and becomes the preview.
`;var ct=r(st);s(ot);var lt=r(ot),ut=r(t(lt),2);s(lt);var dt=r(lt),ft=r(t(dt),3);ft.nodeValue=`.
`;var pt=r(ft);s(dt);var mt=r(dt),ht=r(t(mt));ht.nodeValue=` — the plan a wetrun must match to execute: the one named by
`;var gt=r(ht,2);gt.nodeValue=`, or the one in the host's last-run report when that pass
was a preview, recorded when Zap printed it, whether or not anyone read it, and
withdrawn when its output couldn't be written.
`;var _t=r(gt);s(mt);var vt=r(mt),yt=r(t(vt));yt.nodeValue=` — a detection privilege: root on every connection.
`;var bt=r(yt);s(vt);var xt=r(vt),St=r(t(xt),4);s(xt);var Ct=r(xt),wt=r(t(Ct),9);wt.nodeValue=`, …), checked on its whole rendered value: a
`;var Tt=r(wt,4);Tt.nodeValue=` can't end the directive.
`;var Et=r(Tt);s(Ct);var Dt=r(Ct),Ot=r(t(Dt),3);Ot.nodeValue=` build a config is evaluated with, recorded in
`;var kt=r(Ot,4);kt.nodeValue=`; a missing or mismatched pin refuses.
`;var At=r(kt);s(Dt);var jt=r(Dt),Mt=r(t(jt),10);s(jt);var Nt=r(jt),Pt=r(t(Nt),9);Pt.nodeValue=` /
`;var Ft=r(Pt,3);s(Nt);var It=r(Nt),Lt=r(t(It));Lt.nodeValue=` — privileged commands carry an explicit
`;var Rt=r(Lt,4);Rt.nodeValue=`.
`;var zt=r(Rt);s(It);var Bt=r(It),Vt=r(t(Bt),4);s(Bt);var Ht=r(Bt),Ut=r(t(Ht),2);s(Ht);var Wt=r(Ht),Gt=r(t(Wt),2);s(Wt);var Kt=r(Wt),qt=r(t(Kt),2);s(Kt);var Q=r(Kt),Jt=r(t(Q),14);s(Q);var Yt=r(Q),Xt=r(t(Yt),2);s(Yt);var Zt=r(Yt),Qt=r(t(Zt),7);Qt.nodeValue=` act. Zap's
word for "not a dry run", chosen to be hard to type by accident.
`;var $t=r(Qt);s(Zt);var en=r(Zt),tn=r(t(en),2);s(en);var $=r(en),nn=r(t($),3);nn.nodeValue=`, committed with it.
`;var rn=r(nn);s($);var an=r($),on=r(t(an),3);on.nodeValue=`): caches,
last-run reports, deploy previews, SSH sockets; the installed binary stays in
`;var sn=r(on,2);sn.nodeValue=`. Never part of the plan.
`;var cn=r(sn);s(an),ae((e,ee,te,t,n,r,i,ne,o,s,ie,ae,c,l,u,se,d,f,p,m,h,g,_,v,y,b,he,x,S,C,w,T,E,D,O,k,A,Ce,j,Te,M,N,P,F,I,L,R,z,B,V,H,U,W,G,K,q,J,Y,X,Z,He)=>{a(re,`href`,e),a(oe,`href`,ee),a(ce,`href`,te),a(le,`href`,t),a(ue,`href`,n),a(de,`href`,r),a(fe,`href`,i),a(pe,`href`,ne),a(me,`href`,o),a(ge,`href`,s),a(_e,`href`,ie),a(ve,`href`,ae),a(ye,`href`,c),a(be,`href`,l),a(xe,`href`,u),a(Se,`href`,se),a(we,`href`,d),a(Ee,`href`,f),a(De,`href`,p),a(Oe,`href`,m),a(ke,`href`,h),a(Ae,`href`,g),a(je,`href`,_),a(Me,`href`,v),a(Ne,`href`,y),a(Pe,`href`,b),a(Fe,`href`,he),a(Ie,`href`,x),a(Le,`href`,S),a(Re,`href`,C),a(ze,`href`,w),a(Be,`href`,T),a(Ve,`href`,E),a(Ue,`href`,D),a(Ge,`href`,O),a(Je,`href`,k),a(Xe,`href`,A),a(Qe,`href`,Ce),a(tt,`href`,j),a(at,`href`,Te),a(ct,`href`,M),a(ut,`href`,N),a(pt,`href`,P),a(_t,`href`,F),a(bt,`href`,I),a(St,`href`,L),a(Et,`href`,R),a(At,`href`,z),a(Mt,`href`,B),a(Ft,`href`,V),a(zt,`href`,H),a(Vt,`href`,U),a(Ut,`href`,W),a(Gt,`href`,G),a(qt,`href`,K),a(Jt,`href`,q),a(Xt,`href`,J),a($t,`href`,Y),a(tn,`href`,X),a(rn,`href`,Z),a(cn,`href`,He)},[()=>c(`docs/concepts`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#convergence`),()=>c(`docs/cli#zap-apply`),()=>c(`docs/concepts#convergence`),()=>c(`docs/detection#batches`),()=>c(`docs/targets#the-bootstrap-user`),()=>c(`docs/resources#build`),()=>c(`docs/concepts#the-plan`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#convergence`),()=>c(`docs/configs#the-sandbox`),()=>c(`docs/deploy`),()=>c(`docs/detection#per-resource-depth`),()=>c(`docs/concepts#convergence`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#dry-run-and-wetrun`),()=>c(`docs/detection#privilege`),()=>c(`docs/env#the-env-file`),()=>c(`docs/lock#what-detection-compares`),()=>c(`docs/configs#what-the-gates-reject`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#convergence`),()=>c(`docs/detection#privilege`),()=>c(`docs/detection#the-last-run-report`),()=>c(`docs/lock#standing`),()=>c(`docs/detection#privilege`),()=>c(`docs/env#secrets`),()=>c(`docs/lock#standing`),()=>c(`docs/detection`),()=>c(`docs/concepts#triggers`),()=>c(`docs/lock`),()=>c(`docs/concepts#the-plan`),()=>c(`docs/concepts#the-plan`),()=>c(`docs/deploy#preflight`),()=>c(`docs/deploy#binding-a-wetrun-to-a-reviewed-plan`),()=>c(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>c(`docs/lock#what-detection-compares`),()=>c(`docs/recipes`),()=>c(`docs/env#references`),()=>c(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>c(`docs/concepts#apply-asserts-convergence`),()=>c(`docs/resources`),()=>c(`docs/concepts#a-wetrun-executes-only-the-plan-you-reviewed`),()=>c(`docs/detection#privilege`),()=>c(`docs/targets`),()=>c(`docs/resources#content`),()=>c(`docs/lock#the-toolchain-pin`),()=>c(`docs/lock`),()=>c(`docs/concepts#triggers`),()=>c(`docs/targets#two-tier-privilege-escalation`),()=>c(`docs/env#masked-hosts-and-review`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#convergence`),()=>c(`docs/env#unverifiable`),()=>c(`docs/lock#two-kinds-of-fetched-content`),()=>c(`docs/concepts#detection`),()=>c(`docs/concepts#dry-run-and-wetrun`),()=>c(`docs/lock#who-writes-who-reads`),()=>c(`docs/lock`),()=>c(`docs/lock#on-disk-state`)]),ne(e,n)},$$slots:{default:!0}})},$$slots:{default:!0}}),n()}export{d as t};