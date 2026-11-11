# Glossary

One line per term, with where it's explained. The model itself is in
[concepts.md](./concepts.md).

**Absent** — a detection verdict: the resource isn't present; the planner
creates it. [concepts.md](./concepts.md#detection)

**Additive** — a declared list where each entry must be present and an entry
added by hand is neither detected nor removed: firewall allow rules, `pg_hba`
rules, a user's groups. [concepts.md](./concepts.md#convergence)

**Apply** — `zap apply`: a dry run of the plan by default; with `--wetrun`, the
command that changes the machine. [cli.md](./cli.md#zap-apply)

**Authoritative** — a field made exactly the declared value; anything added by
hand is removed, not merged. One of three field classes, beside additive and
unset. [concepts.md](./concepts.md#convergence)

**Batch** — one shell script per lane carrying every detection read
of a pass, delivered on stdin, run once per pass.
[detection.md](./detection.md#batches)

**Bootstrap user** — `target.bootstrap_user`, the alternate account
`--bootstrap` connects as for a first provisioning run before SSH hardening
locks it out. [targets.md](./targets.md#the-bootstrap-user)

**Build** — the `build` resource: fetch a source archive, verify and pin it,
build it, record its provenance in a sidecar. [resources.md](./resources.md#build)

**Changeset** — the resources the plan will create or update, with their steps.
What `plan_hash` names. [concepts.md](./concepts.md#the-plan)

**Converged** — a detection verdict: the desired state is already present;
nothing to do. Also the state of a machine whose every resource reads so.
[concepts.md](./concepts.md#detection)

**Convergent** — the control model: read the current state, diff it against the
declared state, change only the difference. Re-running is always safe.
[concepts.md](./concepts.md#convergence)

**Declaration** — the JSON a config evaluates to: the target plus every
resource. A pure function of `zap.ts` and the files it reads. [configs.md](./configs.md#the-sandbox)

**Deploy** — `zap deploy`: ship a versioned release to a remote host as
`releases/<version>` plus a `current` symlink, restart, health-check, roll back
on failure. The one imperative command. [deploy.md](./deploy.md)

**Depth** — how much detection reads for a kind: existence, attributes, or
content. Matches the kind's execution idempotency.
[detection.md](./detection.md#per-resource-depth)

**Drift** — the gap between the live machine and the declaration. Found by
reading, every run; never tracked. [concepts.md](./concepts.md#convergence)

**Drifted** — a detection verdict: present but wrong, carrying what was
observed; the planner updates it. [concepts.md](./concepts.md#detection)

**Dry run** — `apply` or `deploy` without `--wetrun`: reads the target, renders
the plan, changes nothing on it.
[concepts.md](./concepts.md#dry-run-and-wetrun)

**Elevated** — a detection privilege: root over SSH; on a local target, the
operator first and `sudo` for a read that failed.
[detection.md](./detection.md#privilege)

**Env file** — a file of `NAME=VALUE` lines loaded with `--env-file`, the source of
reference values alongside the environment. [env.md](./env.md#the-env-file)

**Extract sentinel** — the `.zap_remote_hash` file an extracted `remote` file
leaves in its destination, recording a digest of the tarball pin and the extract
form. [lock.md](./lock.md#what-detection-compares)

**Gates** — the machine-free checks every command runs on the declaration:
secrets and structure. [configs.md](./configs.md#what-the-gates-reject)

**Held** — what happens to an undetermined resource: left out of the plan,
reported, exit 1. A change that depends on a held resource, or would trigger a
held service, is held behind it. [concepts.md](./concepts.md#detection)

**Imperative** — a resource or command that always runs because there is no
stable state to converge to: `pipeline`, `deploy`.
[concepts.md](./concepts.md#convergence)

**Lane** — one of a pass's batches, named for what it runs as: login, or root.
A lane is not a privilege: the root lane carries both the root and the elevated
reads.
[detection.md](./detection.md#privilege)

**Last-run report** — what the most recent detection pass on a host read, kept
under `~/.zap` and rendered by `zap status`; a preview's report holds the plan a
wetrun binds to. [detection.md](./detection.md#the-last-run-report)

**Lock standing** — a tracked pin's classification against the config: current,
missing, stale, unverifiable, or orphan. [lock.md](./lock.md#standing)

**Login** — a detection privilege: the connecting user, unprivileged.
[detection.md](./detection.md#privilege)

**Mask** — removing a resolved secret's value from every output. `zap.mask()` /
`zap.unmask()` say so for a reference the rule reads wrongly. [env.md](./env.md#secrets)

**Operator** — you: the person (or agent) running Zap, whose environment
supplies reference values and whose SSH keys reach the target.

**Orphan** — a last-run resource, or a lock entry, that the config no longer
declares. Warn-only. [lock.md](./lock.md#standing)

**Pass** — one detection of every declared resource against the target: every
read batched, every resource read live. [detection.md](./detection.md)

**Pending trigger** — a marker under `/var/lib/zap/pending/` on the target
recording a restart or reload a run owes a service. [concepts.md](./concepts.md#triggers)

**Pin** — the blake3 of fetched bytes, declared in the config (vendored) or
recorded in `zap.lock` (tracked). [lock.md](./lock.md)

**Plan** — the changeset for one run against one target, and the command that
renders it. [concepts.md](./concepts.md#the-plan)

**`plan_hash`** — the blake3 that names a plan for review and for
`--expect-plan`. It covers the changes, the machine they are for, what each
reference resolves to (a secret only as the fact), and the text Zap's own steps
run. [concepts.md](./concepts.md#the-plan)

**Preflight** — the convergence pass `deploy --wetrun` runs before shipping;
drift or an unreadable resource refuses the release. [deploy.md](./deploy.md#preflight)

**Preview** — a pass that rendered a plan and executed nothing: `zap plan`, a
dry `zap apply`, a refused wetrun. Its plan is the one a wetrun binds to by
default. `zap deploy` keeps its own, the **deploy preview**
([deploy.md](./deploy.md#binding-a-wetrun-to-a-reviewed-plan)).
[concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed)

**Provenance sidecar** — the `<output>.zap-build` file recording a digest of the
source pin a build came from and how it was built. [lock.md](./lock.md#what-detection-compares)

**Recipe** — a shipped pure function returning a config fragment.
[recipes.md](./recipes.md)

**Reference** — `zap.env('NAME')`: a stand-in for an operator-environment
value, inert in the declaration, resolved when Zap acts, shown as `{env:NAME}`.
[env.md](./env.md#references)

**Refused** — a wetrun that didn't execute because its plan wasn't the reviewed
one, or, asked on a terminal, wasn't confirmed (declined). Exit 2; the plan is
rendered and becomes the preview.
[concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed)

**Residual** — a resource that still doesn't read converged after a wetrun's
changes ran. Exit 1. [concepts.md](./concepts.md#apply-asserts-convergence)

**Resource** — one typed unit of desired state with a stable `id`.
[resources.md](./resources.md)

**Reviewed plan** — the plan a wetrun must match to execute: the one named by
`--expect-plan <hash>`, or the one in the host's last-run report when that pass
was a preview, recorded when Zap printed it, whether or not anyone read it.
[concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed)

**Root** — a detection privilege: root on every connection.
[detection.md](./detection.md#privilege)

**Target** — where a config acts: `local: true`, or a host over SSH, with its
package and service managers. [targets.md](./targets.md)

**Template kind** — the form a `template` variable's value is held to
(`hostname`, `port`, `path`, …), checked on its whole rendered value: a
`hostname` in an nginx `server_name` can't end the directive.
[resources.md](./resources.md#content)

**Toolchain pin** — the `fgro` build a config is evaluated with, recorded in
`zap.lock` by `zap lock`; a missing or mismatched pin refuses.
[lock.md](./lock.md#the-toolchain-pin)

**Tracked** — a `remote` file, `build` source, or `apt_repo` signing key with no
pin in the config; the pin lives in `zap.lock`. [lock.md](./lock.md)

**Trigger** — a `file`'s `triggers`, or a `service`'s `restart_on` /
`reload_on`: a change in the source promotes the service to a restart or
reload. [concepts.md](./concepts.md#triggers)

**Two-tier privilege escalation** — privileged commands carry an explicit
`sudo`; on a local target file operations try natively and escalate only when
denied, and over SSH they run under `sudo`.
[targets.md](./targets.md#two-tier-privilege-escalation)

**Unbindable** — a plan whose host, connecting user, or deploy health domain
resolves through a masked reference: it has no `plan_hash`, so no wetrun can
bind to it. [env.md](./env.md#masked-hosts-and-review)

**Undetermined** — a detection verdict: Zap couldn't read the resource and
won't guess. Held. [concepts.md](./concepts.md#detection)

**Unset** — a field the config leaves out: unmanaged, neither set nor
reverted. [concepts.md](./concepts.md#convergence)

**Unverifiable** — a comparing pass whose desired side depended on an unset
reference. Exit 1. [env.md](./env.md#unverifiable)

**Vendored** — a `remote` file, `build` source, or `apt_repo` signing key
pinned by a `blake3` in the config itself (an `apt_repo`'s `key_blake3`). No
lock entry. [lock.md](./lock.md#two-kinds-of-fetched-content)

**Verdict** — detection's answer per resource: converged, drifted, absent, or
undetermined. [concepts.md](./concepts.md#detection)

**Wetrun** — `--wetrun`: the flag that makes `apply` or `deploy` act. Zap's
word for "not a dry run", chosen to be hard to type by accident.
[concepts.md](./concepts.md#dry-run-and-wetrun)

**Withheld** — a tracked pin that isn't current, dropped before detection by
the read-only commands so its resource holds. [lock.md](./lock.md#who-writes-who-reads)

**`zap.lock`** — the pin ledger next to `zap.ts`, committed with it.
[lock.md](./lock.md)

**`~/.zap`** — the operator-side state directory (or `$ZAP_HOME`): caches,
last-run reports, deploy previews, SSH sockets; the installed binary stays in
`~/.zap/bin`. Never part of the plan.
[lock.md](./lock.md#on-disk-state)
