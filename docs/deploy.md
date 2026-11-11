# Deploy

`zap deploy` ships a versioned release of your application to a remote host over
SSH and swaps it in atomically, with a health gate and automatic rollback. The
host is one your config already converges with `zap apply`: the same tool that
built the machine ships the app, and the deploy refuses to ship onto a host that
has drifted from its config.

Deploy is the one imperative command. Each run produces a new release, so there
is nothing to converge to. It still plans before it acts: a dry run prints
every step with the command, script, or URL behind it, and a wetrun executes
only [the plan a dry run showed](#binding-a-wetrun-to-a-reviewed-plan).

## Configuration

```ts
export default (zap) => {
	zap.target({
		host: zap.env('DEPLOY_HOST'),
		user: zap.env('DEPLOY_USER'),
		package_manager: 'apt',
		service_manager: 'systemd',
		home: '/home/app',
	});

	zap.deploy({
		build: 'gro build',
		artifacts: ['build/', 'dist_artifacts/'],
		path: '/home/app/app',
		releases: 5,
		service: 'app',
		shared: ['.env.production'],
		prepare: ['deno cache server.js'],
		health: {domain: zap.env('DEPLOY_DOMAIN'), path: '/health', attempts: 15, interval_ms: 2000},
	});
};
```

| Field | Required | Meaning |
|---|---|---|
| `build` | no | command run locally before packaging; omit it, or pass `--skip-build`, and the plan has no build step |
| `artifacts` | yes | files and directories, relative to the directory you run `zap` from, packaged into the release. An entry can't begin with `-` (`tar` would read it as an option; write `./-name`) or with `@` (which some `tar`s read as an archive to include) |
| `path` | yes | the remote app root: holds `releases/`, `shared/`, and the `current` symlink. An absolute path, written out (no reference, no `~`); it must exist and be writable by the connecting user, which `zap apply` usually arranges |
| `releases` | no | how many releases to keep, the live one included (default 5). At least 2: the release just deployed and the one it replaced are always kept, since a failed deploy rolls back to the second |
| `service` | no | the service restarted after the swap; requires `target.service_manager`; takes no reference |
| `shared` | no | files under `<path>/shared/` symlinked into each release root. Each entry is a relative name of a file: no `..` component, no control character, not ending in `/` or in a `.` component (`config/.`); anything else is rejected by the structural gate. Each must exist (`zap apply` usually writes it): the deploy fails before extracting otherwise |
| `prepare` | no | commands run on the target in the new release, as the connecting user, before the swap, each in a shell of its own; the release is still under a hidden staging name then, so a command shouldn't record its absolute path |
| `health` | no | the post-restart health gate, below |

### `health`

| Field | Required | Meaning |
|---|---|---|
| `domain` | yes | the host polled over HTTPS; usually a `zap.env('DEPLOY_DOMAIN')` reference |
| `path` | yes | the request path, beginning with `/` (`/health`, or `/ready` to make it the gate); takes no reference |
| `attempts` | no | polls before the deploy fails (default 15), at least 1 |
| `interval_ms` | no | delay between polls in milliseconds (default 2000) |

Omit the block to deploy with no health gate and no readiness check; there is no flag to disarm a
declared one.

## Commands

```sh
zap deploy                             # dry run: the whole plan and its plan_hash, recorded as the preview
zap deploy --wetrun                    # ship the previewed plan: build, upload, swap, restart, health-check
zap deploy --wetrun --expect-plan <hash>   # ship only the plan with this hash
zap deploy --wetrun --skip-build       # no build step: ship the local artifacts as they are
zap deploy --wetrun --skip-preflight   # ship without the drift preflight
zap deploy --wetrun --force            # ship an unchanged version, or a dirty tree
zap deploy --wetrun --json             # stream step events as JSON lines
```

A wetrun binds to a preview made with the same plan-changing flags
([below](#binding-a-wetrun-to-a-reviewed-plan)). `--env-file <path>` loads the
operator env first, as for every command. Flags, exit codes, and what a dry run
reads: [cli.md](./cli.md#zap-deploy).

**What it needs.** On your machine: `git`, `tar` with `gzip`, and `ssh`, with `zap` run from
inside the application's git checkout. On the target: what a file write needs
([targets.md](./targets.md#what-the-target-needs)), plus `tar`, `id`, and
`flock`.

### What a wetrun prints

While a wetrun runs, each phase prints one line to standard error as it starts:
the drift preflight, each step, and a rollback if one starts. Nothing about how
a phase ended prints there. When the run ends, the report goes to standard
output: a table with a row for the preflight, each step, and a rollback when
one ran, each with its status, how long it took, and what it says (the
upload's size, what the health and readiness checks found, a failed step's
error, a skipped one's reason; a command's own output, such as the build log,
is left out), then the warnings and a closing line that says what is live
where.

```
→ preflight: checking 1 apply-managed resource for drift
→ build: Build application
→ tarball: Create tarball
→ upload: Upload tarball
→ extract_swap: Extract and swap release
→ restart: Restart app
→ health: Health check
deploy — target host.example (wetrun)
  version: abc1234 (previous: def5678)
  ok    preflight     4.1s  1 apply-managed resource, no drift
  ok    build         1.1s
  ok    tarball       2.2s
  ok    upload        3.3s  4.2 MB sent
  ok    extract_swap  4.4s
  ok    restart       5.5s
  ok    health        6.6s  healthy after 2 attempts
deployed abc1234 to host.example (previous: def5678) in 1m 23s
plan_hash: deadbeef
```

The `→` lines are standard error and the rest standard output, so standard
output redirected to a file holds the whole report and no progress line. Under
`--json` neither prints: the events stream instead
([cli.md](./cli.md#json-events)). A preflight that checked nothing is a `skip`
row that says why (`--skip-preflight`, or no apply-managed resources declared).

A failed run's closing line names the step that failed and the state the
target is in. A failure before the swap released nothing:

```
deploy FAILED at upload on host.example after 1m 23s — nothing was released, and `current` was not moved
```

A failure of the extract-and-swap step itself is read back from `current`, and
nothing is rolled back. When `current` names another release, or none on a
first release, this one is not live:

```
deploy FAILED at extract_swap on host.example after 1m 23s — `current` does not name this release, so nothing was released
```

When it names this version (the swap can have happened before the step failed,
or another deploy of the same version swapped), or can't be read, the line
claims neither way and points at the step's error. So does a `current` that
reads as missing where a release was live before the run: Zap never removes
`current`, so that read is one it can't believe (an app path the connecting
user can no longer search reads that way):

```
deploy FAILED at extract_swap on host.example after 1m 23s — the swap is not known to have completed, and nothing was rolled back (see the step's error above)
```

A failure after the swap is followed by a rollback
([Auto-rollback](#auto-rollback)).

## First deploy

A first deploy onto a fresh host is a chicken-and-egg: the binary lands via
`deploy`, but `deploy`'s preflight requires a converged `apply`, and a `service`
declared `running: true` can't be running before there is anything to run.
Resolve it in the config: declare the service `enabled` and leave `running`
unset.

```ts
zap.service({
	id: 'app-service',
	service: 'app',
	enabled: true,
	// no `running`: zap manages enablement, not runtime state, so the service
	// doesn't drift before a binary exists; the deploy's restart starts it
	restart_on: ['app-unit'],
});
```

Then the bring-up is two reviewed runs: `zap apply`, then `zap apply --wetrun`,
provisions the host (firewall included, so deploying first would bail), and
`zap deploy`, then `zap deploy --wetrun`, ships the first release, whose
restart step starts the service. Preview the deploy after the apply has run:
the dry run connects as the user the apply sets up, and a pin the apply writes
to `zap.lock` is part of the deploy plan.

The trade is explicit: a config that leaves `running` unset tells Zap never to
assert that the app is up, so `zap apply` on a host whose daemon crashed and
stayed down reports converged. Declaring `running: true` buys that assertion
back at the cost of one `deploy --wetrun --skip-preflight` on the very first
release (previewed with `deploy --skip-preflight`, since the flag is part of
the plan), and `--skip-preflight` disables the whole drift gate for that run.

When SSH hardening changes the user Zap connects as, add `--bootstrap` to the
first apply: [targets.md](./targets.md#the-bootstrap-user).

## Binding a wetrun to a reviewed plan

A dry run prints the whole plan and ends with its hash. It comes in groups a
blank line apart: what ships where (the version and the release it replaces,
the commit's subject, the host and the user Zap connects as, who is deploying,
the declared target, and what the references resolve to), the two gates (the
tree and the drift preflight), the steps, and what the run does with the plan.
The commit's subject is its own first line, cut at 100 characters, with any
secret's value masked; on a dirty tree it is still the commit's, and its line
says it is the commit under the uncommitted changes. The extract-and-swap step
lists the values its script is built from above the script: the app path, the
release `current` must still name, each `shared` link, each `prepare` command,
and how many releases are kept. Each poll's first line says what it does and
how long it can take; a second gives the URL as declared when a reference in it
resolves. Last, `in short:` restates the commit, version, host, user, tree, and
preflight beside the hash, below however long the script is:

```
deploy — target {env:DEPLOY_HOST} (dry-run)
  version: 3f2a9c1e7b04 (previous: 8d41e0a6c2f9)
  commit: Add the readiness gate
  host: app.example.com
  user: app
  deployed by: ops@laptop
  target: {"local":false,"host":{"$env":"DEPLOY_HOST"},"user":{"$env":"DEPLOY_USER"},"home":"/home/app","package_manager":"apt","service_manager":"systemd"}
  references:
    DEPLOY_DOMAIN = app.example.com

  tree: clean
  preflight: no apply-managed resources declared — nothing to check

  - Build application (build)
      local$ gro build
  - Create tarball (tarball)
      local$ tar -czf "$ZAP_DEPLOY_ARCHIVE" -- 'build/' 'dist_artifacts/'
      writes $ZAP_DEPLOY_ARCHIVE: a file in a private directory of this run, removed when it ends
  - Upload tarball (upload)
      the archive → target:/home/app/app/.zap-deploy-app-3f2a9c1e7b04.tar.gz (as the connecting user, mode 600, checked against its SHA-512)
  - Extract and swap release (extract_swap)
      app: /home/app/app
      replaces: 8d41e0a6c2f9 — `current` must still name it
      links: shared/.env.production
      prepare: deno cache server.js
      keeps: 5 releases, counting this one and 8d41e0a6c2f9
      target script (its stdin: the archive's SHA-512):
        set -e
        zap_archive='/home/app/app/.zap-deploy-app-3f2a9c1e7b04.tar.gz'
        …
  - Restart app (restart)
      target$ sudo systemctl daemon-reload && sudo systemctl restart app
  - Health check (health)
      GET https://app.example.com/health — healthy on 2xx; up to 15 attempts, 2s apart, 5s each (1m 43s at most)
      declared as https://{env:DEPLOY_DOMAIN}/health
  - Readiness check (readiness)
      GET https://app.example.com/ready — ready on 2xx, unserved on 404; up to 15 attempts, 2s apart, 5s each (1m 43s at most)
      declared as https://{env:DEPLOY_DOMAIN}/ready

  (dry-run — re-run with --wetrun to deploy)

  in short:
    commit: Add the readiness gate
    version: 3f2a9c1e7b04 (previous: 8d41e0a6c2f9)
    host: app.example.com
    user: app
    tree: clean
    preflight: no apply-managed resources declared — nothing to check
plan_hash: 2d09162e11f59e2b2409f6d89dcf0f469a877baf09d6e9f770bf5218eb6fcb95
```

A wetrun executes only a reviewed plan: one whose hash you named, or one Zap
printed as a preview. It computes its plan again, and that plan's hash must
equal the reviewed one:

- `--expect-plan <hash>` names the reviewed plan explicitly, and binds alone;
- with no flag, the reviewed plan is the **deploy preview** recorded for this
  config and host: the last `zap deploy` dry run, or a wetrun that refused.

Otherwise the wetrun **refuses** before the drift preflight and any step,
prints the plan it would have run under a `REFUSED` banner that says why (no
preview yet, the plan changed since the preview, or the hash doesn't match),
records that render as the new preview, and exits 2. Nothing is built or
uploaded. The everyday flow is `zap deploy`, read it, `zap deploy --wetrun`
with the same flags. A wetrun fired cold becomes the preview, and the next one
executes if nothing moved. There is no flag that skips the review, and a dry
run rejects `--expect-plan`.

The preview is recorded when Zap prints it, not when anyone reads it. A dry run
whose output couldn't be written is withdrawn, so the next wetrun run without
`--expect-plan` refuses; one sent to `/dev/null`, or cut short by `head` after
the pipe took it whole, still binds it. When the output may be truncated, or
the one who reads the preview isn't the one who deploys, pass `--expect-plan`
with the hash on the preview's last line
([concepts.md](./concepts.md#a-wetrun-executes-only-the-plan-you-reviewed)).

On an interactive terminal (standard input and standard error both terminals),
a wetrun with no review and no `--expect-plan` shows the plan instead, under an
`UNREVIEWED` banner, then its recap and its `plan_hash`, and ends with the
question:

```
  …

  UNREVIEWED — nothing has run: this plan runs only once it is confirmed below.
    no deploy plan has been previewed for this host.

  in short:
    commit: Add the readiness gate
    version: 3f2a9c1e7b04 (previous: 8d41e0a6c2f9)
    host: app.example.com
    user: app
    tree: clean
    preflight: no apply-managed resources declared — nothing to check
plan_hash: 2d09162e11f59e2b2409f6d89dcf0f469a877baf09d6e9f770bf5218eb6fcb95
Deploy this plan? Type 2d09162e, the start of its plan_hash, to confirm:
```

Typing those eight characters back is the review: the wetrun goes on with
exactly the plan shown, to the drift preflight, the withdrawal of any recorded
preview, and the steps, as a bound wetrun does. Any other answer is the refusal
above, under a `DECLINED` banner. The prompt follows `zap apply`'s rules: no
flag answers it, `--json` never asks, and a script stays non-interactive by
previewing first, passing `--expect-plan`, or running with standard input that
isn't a terminal ([cli.md](./cli.md#zap-apply)).

One recorded preview covers one execution: a wetrun that passes the review and
the preflight withdraws it before its first step, so a deploy that fails needs a
new preview (or `--expect-plan`) before it runs again, and of two wetruns
started on one preview only one goes on. An `--expect-plan` hash is not
single-use. A preflight bail or an already-deployed exit leaves the preview in
place. A preview doesn't expire.

The preview is a small file under `~/.zap`
([lock.md](./lock.md#on-disk-state)), separate from the last-run report that
`zap apply` binds to: a `zap plan` doesn't disturb a deploy preview, and a
deploy dry run doesn't disturb a convergence one. It holds the hash, not the
plan. A deploy wetrun's drift preflight does replace the convergence record: it
records its pass as the last-run report, which is no preview, so a `zap apply`
previewed before it needs a new preview before its wetrun. With no state
directory nothing is recorded, the run says so, and only `--expect-plan` binds.

Everything the hash covers is printed but two of Zap's own scripts: the one the
upload installs the archive with, and the swap the auto-rollback runs. So a plan
reviewed under one `zap` build doesn't bind one whose scripts differ. It covers:

- the version, the subject line of its commit, the tree state, and the
  previous release on the target;
- the declared target, the host it resolves to, and the connecting user;
- who is deploying (`user@host` of the operator machine, recorded in
  `deploy_info.json`);
- the preflight's state: skipped, nothing declared, or which apply-managed
  resources it checks, as a count and a digest of their declarations and the
  current pins `zap.lock` holds for them;
- every step: the build and tarball commands, the upload paths and the script
  that installs the archive, the remote script and the values it is built from
  (the app path, the `shared` links, the `prepare` commands, how many releases
  are kept), the restart command, the health and readiness URLs as they resolve
  and the budget each is polled with (the attempts, the wait between two, the
  time each is given), and the swap the auto-rollback would run;
- the plan's warnings, printed under it (a `deploy.service` the target's
  service manager can't restart);
- the value of each reference the `deploy` block uses (its health domain),
  printed in its `references:` block (a secret's value excepted: the plan
  records only that it is one).

So a plan reviewed for one host, tree, flag set, or operator does not bind a
wetrun for another: a new commit, a deploy or rollback by someone else in
between, an edit to any declared resource, a changed pin in `zap.lock`,
`--force` on a dirty tree, `--skip-build`, `--skip-preflight`, or `--bootstrap`
each make a different plan. The hash is printed, and the preview recorded, only
when the steps are shown: an already-deployed dry run does neither, so a
redeploy binds to the plan a `--force` dry run shows.

It does not cover:

- the artifact bytes. The version names the commit, and the plan says whether
  the tree was dirty, but what the build produces is not hashed. The review
  covers the script that verifies the archive it was sent, not the archive.
- the values a resource's references resolve to. The digest takes
  each declaration as written, so it is the same in every environment; the
  environment reaches the hash only through the host, the connecting user, and
  the health domain. The same holds for the bytes of a local `source` file.

**A masked host, connecting user, or health domain can't be deployed to.** No
review can bind such a plan: a wetrun is an error that names the reference
before anything runs, and a dry run shows the plan under an `UNBINDABLE` note,
with no `plan_hash` and no recorded preview. The ways out:
[env.md](./env.md#masked-hosts-and-review).

Text from the config, the environment, the checkout (the commit's subject), and
the target is printed with control characters written out as `<U+XXXX>`, so a
value can't hide or forge a line of the preview
([security.md](./security.md#escaped-output)).

## Preflight

Before deploy touches the network, the machine-free gates run (secrets,
structure, and, for a deploy config, a present `health.domain`), and a wetrun
rejects any unset reference and a host, connecting user, or health domain behind
a masked reference. `zap.lock` is read here too, when the drift preflight will
check. `--skip-preflight` doesn't skip the gates.

Then a wetrun checks its [review](#binding-a-wetrun-to-a-reviewed-plan) and runs
the **drift preflight**: the convergence pass against the config, before
building or uploading. If apply-managed state (an nginx site, the
env file, the service unit) was edited in the config but never applied, shipping
a new artifact against it would be a silent mismatch; the preflight bails with
exit 2, and a change held behind a resource it couldn't read counts as drift. A
`pipeline`, which detects absent and runs on every apply, is not drift, and
neither is a service that changes only because its trigger fires, planned or
held: it reads converged, no pending restart or reload is recorded for it, and
every source that fires it is itself not drift (a pipeline, or another such
service). A service that also drifted, one owed an action an earlier apply
never completed, or one fired by any other change is drift.
It also bails, with the same code, when any resource is `undetermined`: a gate
that couldn't check everything doesn't pass by default.

After a drift bail, review the changes with `zap apply`, converge with
`zap apply --wetrun`, and re-run the deploy: its review still binds unless
`zap.lock` changed.

`--skip-preflight` skips the drift preflight, and a config that declares no
apply-managed resources has nothing to check. Either way the plan says so on its
`preflight:` line.

The deploy also refuses when the live release already has this version, on a
dry run too (`server already at this version`, exit 0). `--force` ships anyway.
A `current` that names this version but whose release isn't on the host serves
nothing, so it isn't refused: the run plans a redeploy and warns that `current`
names a release that is not on the host.

### Dirty trees

A tree with uncommitted changes or untracked files git doesn't ignore deploys
only under `--force`, as `<hash>-dirty-<id>`. Without it, a wetrun is refused
before the target is contacted (exit 2), since the release would ship the tree
under the commit's version; a dry run shows the plan
(`tree: uncommitted changes or untracked files`) with no hash, records nothing,
and says the wetrun is refused, even when the commit is the live release.

The id is 8 lowercase hex of a blake3 over what the tree adds to the commit, so
the same tree gets the same id (a dry run and its wetrun agree) and a second
dirty tree on one commit is a release of its own:

| In the tree | Counts by |
|---|---|
| tracked and staged changes | `git diff HEAD --binary` |
| an untracked file git doesn't ignore | its name and contents |
| an untracked symlink | the path it points to, as git records one, whether that is a file, a directory, or nothing |
| an untracked nested repository | its name alone |
| a submodule | its commit and whether its own index shows changes, not what they are |
| a sparse checkout | the files outside its cone, as deletions: the tree reads dirty |

Zap reads the tree against a copy of the index's entries that holds no
timestamps or flags, so every file is compared by its contents: a file the
index marks unchanged (`assume-unchanged`, `skip-worktree`) counts like any
other, and so does one whose timestamps the index's cache would take for
unchanged. Each read compares against the objects the commit names, not ones a
`refs/replace/` entry puts in their place (`--no-replace-objects`, as the
subject line is read too), and sets `core.fsmonitor=false`,
`core.untrackedCache=false`, `core.ignoreStat=false`, `core.fileMode=true` (a
mode change counts), `core.autocrlf=false` (line endings are not converted), and
`core.splitIndex=false`, and passes `--untracked-files=normal` and
`--ignore-submodules=none`, so `status.showUntrackedFiles`, a submodule's
`ignore` setting, and `diff.ignoreSubmodules` don't narrow it either. So a
checkout on a filesystem without executable bits, or one checked out with
`core.autocrlf=true`, reads dirty, and deploys only under `--force`.

Two things still decide what counts as a change. The checkout's attributes
(`.gitattributes`, `.git/info/attributes`) are applied: a clean filter, LFS
among them, or an `eol` or `text` attribute can make a file that differs from
the commit compare equal to it, and no flag turns them off. A submodule's own
index is read as it is, so an `assume-unchanged` edit or stale timestamps
inside one can read clean.

A sparse checkout reads dirty and deploys only under `--force`: the files
outside its cone aren't there, so the tree the build sees is not the commit's.

A tree Zap can't read is an error that says what git said, not a clean tree.

## The release mechanism

Once the [preflight](#preflight) passes, a wetrun runs these steps in order:

```
build (local) → tarball → upload → extract + swap → restart → health → readiness
```

1. **build**: run `deploy.build` locally (`gro build`, `cargo build --release`,
   whatever produces your artifacts). With `--skip-build`, or when no build
   command is declared, the plan has no build step.
2. **tarball**: package `deploy.artifacts` into a release archive, a file in a
   private directory of this run on your machine, removed when the run ends.
3. **upload**: install the archive into `<path>` as the connecting user, mode
   `600`, under `.zap-deploy-<user>-<version>.tar.gz`. It is staged beside that
   name and checked against its SHA-512 before it is renamed in, so a transfer
   cut short installs nothing. The archive is held in memory while it uploads.
4. **extract + swap**: one remote script, generated deterministically and
   printed whole by the dry run, does the release-directory work. It reads the
   archive's SHA-512 on its stdin, opens the archive once, requires it to be the
   connecting user's own file, writable by no one else, with that digest, and
   extracts through the open file, so another account on the host can't swap
   the archive between the upload and the extraction. Extracted files belong to
   the connecting user, under that user's umask, without set-id bits on files.
   The script removes the archive on every exit of its own. Then:
   - **lock**: take the app's deploy lock, a kernel `flock` on
     `<path>/.zap-deploy.lock`, held until the script exits. The file is never
     removed and holds no data; when Zap creates it, other users get no
     permission on it. It is opened read-only, so the connecting user and its
     group can hold it, the group even under a umask that gives it read alone
     (022). A deploy that finds the lock held stops at once, before it touches
     `releases/`, with `another deploy is running for this app` (exit 1); it
     doesn't wait. The kernel releases the lock when the script's process ends,
     however it ends; a lock held by a hung deploy is cleared by ending that
     process (`fuser <path>/.zap-deploy.lock` names it). The `prepare` commands
     run with the lock's descriptor closed, so a process one of them leaves
     running doesn't keep the lock once the script ends;
   - **recover**: under the lock, repair what an unfinished deploy (killed, or
     its connection cut) left in `releases/`: a staging directory is removed,
     and a release it had moved aside is put back under its version when that
     name is empty, or removed when it is filled. So a `current` that a killed
     `--force` left naming nothing resolves on the next deploy (a redeploy of
     that version needs no `--force`: [Preflight](#preflight)). Each repair is a
     warning in the run's text report (not in a `--json` stream), and happens
     even when that deploy then fails;
   - **check**: still under the lock, confirm `current` names the release the
     plan read as live (by the link's last segment, trailing slashes dropped;
     nothing at all at `current`, no link and no file or directory, on a first
     deploy). A deploy planned before another one swapped stops here, saying
     `current` changed since this deploy was planned (exit 1), having made
     nothing of its own; run `zap deploy` again. So the release a rollback
     returns to, and the one the prune keeps, is the one live just before this
     deploy's swap. A plan that couldn't read `current` (it warns) stops here
     too when the host has one;
   - extract into a fresh hidden directory, `<path>/releases/.zap-stage`;
   - **link shared**: symlink each `deploy.shared` entry from `<path>/shared/`
     into the new release (an apply-managed env file, for example); a release
     that ships a directory at a shared name fails the deploy here;
   - **prepare**: run each `deploy.prepare` command in the new release, before
     the swap, in a shell of its own (`sh -ec`): an `exit` or `exec` in one ends
     that command, not the script, and a command that fails stops the deploy
     before the swap. Its working directory is the hidden one, not the release's
     final path, and its output goes to the script's error stream: a step
     that fails shows the script's own reason when it stopped itself, or else the
     stream's last lines, and what a command prints becomes no run warning. A
     command that reaches the script's own output anyway (through `/proc`, or a
     descriptor it was handed) can print a line the script marks, a warning or
     its reason for stopping, which is then read as the script's: text only,
     since what the deploy does turns on the exit status and the swap;
   - **place**: rename the complete release to `<path>/releases/<version>`,
     where the version is the commit's hash abbreviated to 12 hex digits
     (`git rev-parse --short=12`, longer only where 12 would be ambiguous), with
     `-dirty-<id>` for a forced dirty tree, above. When that name already exists (an earlier
     deploy of the same version, or the live release under `--force`), it is
     renamed aside first, to `.zap-old-<version>`, and removed after the swap,
     so a release never mixes files from two archives. A run that fails before
     this point leaves no hidden directory and changes no release beyond what it
     recovered; under `--force` of the live version, `current` names nothing for
     the instant between the two renames, and a run that fails after this point
     leaves the new contents live under that name, the old ones not kept. A run
     killed between the two renames leaves the old release aside for the next
     deploy's recovery to put back;
   - **swap**: re-point `<path>/current` at the new release atomically. From
     here the release is live, and the run goes on to restart and check it
     whatever the rest of the script does: what follows is housekeeping, and
     a failure there is a warning in the run's output, not a failed step. A
     script that fails after saying it swapped is taken as swapped only when
     `current`, read again, names the new release;
   - **record**: write `<path>/deploy_info.json` (version, who, when, previous release);
   - **prune**: keep `deploy.releases` releases: the one just deployed, the one
     it replaced, then the newest others. Only a directory named the way Zap
     names a release (a commit hash of 4 to 64 hex digits, alone or with `-dirty-<id>`) is
     ever removed; anything else under `releases/` is left alone. As a
     guard, the prune removes nothing unless `current` names a release, and
     on a target with no `sort` it removes nothing and warns.
5. **restart**: restart `deploy.service` through the target's service manager
   (with a `daemon-reload` first on systemd).
6. **health**: poll `https://<domain><path>` from the operator machine (the one
   you run `zap` on) until
   it answers 2xx, up to `attempts` times, `interval_ms` apart, each attempt
   given 5 seconds. The plan states the most a poll can take. Neither poll
   follows a redirect: a 3xx is not healthy or ready, so a release that
   redirects to a login page doesn't pass on that page's 200.
7. **readiness**: when `health.path` isn't already `/ready`, poll `/ready` too.
   2xx proceeds. When the attempts run out, the last HTTP status decides; a connection failure
   after it doesn't replace it. A **404**
   means the app doesn't serve `/ready`: the step is recorded as `skipped`,
   warns loudly, and the deploy proceeds on liveness alone. Any other answer
   fails the deploy and rolls back: a 503 (the convention for a database schema
   that doesn't match the running code, or an unreachable database), any other
   status, or no answer at all. Point `health.path` at `/ready` to make that one
   check the gate; then any non-2xx, 404 included, rolls back.

## Auto-rollback

If a step after the swap fails (the restart errors, health never goes green,
`/ready` answers 503), Zap re-points `current` at the previous release,
restarts, and re-checks health (the health URL, not `/ready`), recording the
rollback as a row of the report and as step events. The deploy still exits 1:
rollback restores service, it doesn't paper over the failure.

The rollback has its own row in the report, after the failed step, and the
closing line says where it left the target:

```
→ preflight: checking 1 apply-managed resource for drift
→ build: Build application
→ tarball: Create tarball
→ upload: Upload tarball
→ extract_swap: Extract and swap release
→ restart: Restart app
→ health: Health check
→ rollback: Roll back to def5678
deploy — target host.example (wetrun)
  version: abc1234 (previous: def5678)
  ok    preflight     4.1s  1 apply-managed resource, no drift
  ok    build         1.1s
  ok    tarball       2.2s
  ok    upload        3.3s  4.2 MB sent
  ok    extract_swap  4.4s
  ok    restart       5.5s
  FAIL  health        6.6s  service did not become healthy at https://app.example.com/health within 15 attempts (last: HTTP 502)
  ok    rollback      8.0s  def5678 restored and restarted, health OK
  this deploy spent its review: before re-running, preview again with `zap deploy` (or pass --expect-plan with the hash that preview prints)
deploy FAILED at health on host.example after 1m 23s — rolled back: def5678 is live again
plan_hash: deadbeef
```

Without a health check in the plan, the line says the previous release was
restored and restarted, not that it is live. A rollback that didn't go as
planned says so on its row and in the closing line, and a warning below the
table says why: no release was known to return to, so the failed release is live
(the row has no time: it never started); the previous release was restored,
but its restart or its health check failed, so it is not confirmed serving; the
rollback was skipped, so `current` is as the warnings say; or the re-point
itself failed, so the host may be serving the failed release.

The re-point is a compare-and-swap under the app's deploy lock, taken without
waiting. It moves `current` back only while `current` still names this deploy's
release and the previous release is still on the host. Otherwise (another
deploy holds the lock or has replaced the release, someone re-pointed `current`
by hand, `current` names nothing, or the previous release is gone) the rollback
is skipped with a warning that says why: nothing is re-pointed or restarted, and
the deploy still exits 1.

There is nothing to roll back to on a first deploy, or on a `--force` redeploy
of the live version: `current` stays at the failed release, and the run warns
that a manual rollback is needed.

When the restored release's health check fails too, the rollback step is
recorded as failed, and the warning says manual intervention is needed.

The previous release is read from the live `current` symlink at deploy time,
not from a recorded file, so a manual rollback done by hand is seen correctly
on the next deploy. A `current` whose last segment, trailing slashes dropped,
is no release's name names no previous release, so the deploy refuses before
it builds anything: point `current` at the live release by hand, or remove it
to deploy as onto a fresh host.

A `current` that can't be read (the read fails, or the app path is there but
the connecting user can't enter it) leaves the deploy with no previous release:
the preview warns, with the reason, that there is nothing to roll back to. An
app path below a directory the connecting user can't search reads as missing,
so the preview says `(first release)` with no warning; its wetrun then fails at
the upload, before anything is released.

### Concurrent deploys

A deploy planned before another deploy's swap stops at its check (step 4), so a
rollback never undoes a newer deploy, with one exception: a `--force` redeploy
of the same version, planned after a deploy's swap while that deploy is in its
health check, writes the same `current`, which the first deploy's rollback
can't tell from its own and can undo. A rollback skipped because another deploy
held the lock leaves `current` at the failed release if that other deploy then
fails before its own swap; the warning says to check it.

The lock covers the release-directory work only: the restart and the health
checks run after the script releases it, so a deploy can report on a host that
another deploy has since moved on. Two simultaneous deploys of one version by
one connecting user upload to the same name, so either can replace or remove
the other's archive; the other then stops at its digest check or finds no
archive (exit 1) rather than ship bytes it didn't build.
