# How Zap compares

Zap converges the inside of Linux machines you own and ships your services to
them. It is a TypeScript declaration and a Rust engine over SSH, with dry run by
default, no agent, and no server. This page puts it next to the tools you might
otherwise reach for. It is written for someone with a few servers and a laptop,
not a fleet, and it covers when _not_ to use Zap as much as when to.

Facts about other tools name versions where they matter. If something here is
out of date, please file an issue.

What Zap is: [introduction.md](./introduction.md), including the [things it
does differently](./introduction.md#what-zap-does-differently). The
verdict comes first; the side-by-side tables are [at the end](#at-a-glance).

## Use Zap when

- You run a handful of Debian/Ubuntu or Alpine hosts you reach by SSH, and want
  their packages, users, SSH hardening, firewall, nginx, services, and an on-box
  PostgreSQL declared in one file.
- You want nothing on the target beyond `sshd`, `sudo`, and a stock shell and
  core tools: no agent, no Python, no server, no state bucket.
- An AI agent or a non-ops teammate will drive the tool, and you want the default
  command to be harmless, a plan they can show you with a hash, exit codes that
  separate "converged" from "drifted" from "couldn't tell", and typed events
  rather than log scraping.
- You'd rather be told "I couldn't read this" than have a tool guess.
- You deploy your own service as release directories with a health gate and
  rollback, and want the deploy to refuse when the host has drifted.
- You prefer TypeScript with completion over YAML with a template language.

## Don't use Zap when

- **You need many hosts in parallel or fleet orchestration.** One config, one
  host, resources in order. Ansible, pyinfra, Salt.
- **You need cloud resources.** VPCs, DNS, load balancers, managed databases.
  OpenTofu, Terraform, Pulumi; they pair with Zap.
- **You need removing a declaration to remove the thing.** Zap only reports
  orphans. NixOS, or Terraform for cloud resources.
- **You need macOS, Windows, RHEL, Arch, or network devices.** Ansible, chezmoi,
  mise.
- **You want whole-system rollback or reproducibility.** NixOS, image-based
  systems.
- **You're container-native.** Kamal, Compose, Dokku, Coolify; Zap can still
  converge the host underneath.
- **You need branching on mid-run results.** Ansible, or a script.
- **Your machine can't run `fgro`.** It needs x86_64 Linux with Landlock ABI 6
  (kernel 6.12 or later).
- **You need a module ecosystem and community support.** Zap is pre-alpha with
  one maintainer. Ansible.

## Head to head

Ordered by how often a reader is choosing between the two.

### Versus Ansible

The closest in operational shape: agentless, SSH, no server. The furthest in
control model. An Ansible playbook is an ordered list of tasks; most modules
converge within one task (`state: present`), but the playbook is a procedure,
and decisions are made at run time against gathered facts, including facts an
earlier task in the same run changed. Zap has no task order you author: you
declare resources and dependencies, and the engine decides create, update, or
skip from detection.

Ansible's `--check` mode is opt-in and its fidelity depends on each module:
`command` and `shell` are simulated only when given `creates` or `removes`.
Handlers notified by a task are lost if a later task fails, unless you set
`--force-handlers`; Zap remembers an owed reload on the host. Ansible needs
Python on the managed node for nearly every module; Zap needs a shell. Ansible's
`validate:` on `copy` and `template` matches Zap's `validate` on a `file`.

**Reach for Ansible** for its enormous module ecosystem, for fleets and
inventories, for Windows and network devices, or for run-time procedural
flexibility. Zap is narrower and younger by orders of magnitude.

### Versus pyinfra

The closest living tool to Zap's shape: agentless, SSH, generates shell so the
target needs no Python, written in a real language, two-phase (facts first,
then operations). The differences are where the two draw their lines. pyinfra
lets deploy code read facts while deciding what to do, so the declaration can
depend on the host; Zap seals the declaration before contact and doesn't read the
host while deciding. pyinfra shows its changes and
prompts before acting, and warns the list may be incomplete; Zap's dry run is
the default and executes nothing. pyinfra has no lock file pinning fetched content,
no held verdict, and no re-read after acting. pyinfra runs many hosts in
parallel; Zap runs one.

**Reach for pyinfra** for Python, for parallel multi-host runs, or when you want
the host's facts to shape the deploy.

### Versus Docker Compose, Kamal, and self-hosted PaaS

For a solo developer with a VPS, this is the realistic alternative. Compose, and
platforms like Dokku, Coolify, and CapRover, assume a prepared Docker host and
own the application layer: images, containers, routing, often TLS. They don't
converge the host: SSH hardening, the firewall, users, an on-box PostgreSQL,
unattended upgrades. CapRover and a self-hosted Coolify run a control plane on
your server that you have to keep; Coolify's hosted cloud keeps it for you, over
servers that are still yours to converge. Dokku is `git push` to one box.

Kamal 2 ships Docker images and does rolling restarts behind `kamal-proxy`,
which health-checks the new container before switching traffic, a gate that is
stronger than Zap's post-swap health check plus rollback. Kamal has no dry run.
`kamal setup` installs Docker but doesn't otherwise manage the host.

Zap deploys release directories, not containers, and its isolation comes from
converging the host (a hardened systemd unit, a dedicated user) rather than from
an image. The two are complementary: Zap can converge the box these tools run
on.

**Reach for Kamal or Compose** when you're container-native or want multi-host
deploys; for Coolify or Dokku when a UI or `git push` is the experience you want
and you're happy to run their control plane.

### Versus OpenTofu, Terraform, and Pulumi

The closest in discipline: declarative, converge, review a plan before acting.
Terraform's plan is computed by refreshing a **state file** that is the
authoritative record of what Terraform owns, and `data` sources read live
infrastructure during planning, so the desired state is a function of config,
state, and the world. Zap's declaration is a function of the config alone;
detection decides only which declared changes run. There is no state file: the
machine is read every run, and `zap.lock` pins content, not resources.

Credit where due: Terraform's saved plan (`plan -out`, then `apply <planfile>`)
is the most operationally binding plan artifact in the field, and it refuses a
plan whose state has moved since. Zap's wetrun binding does the same job for a
machine, by hash. Terraform also **destroys** a resource you stop declaring;
Zap only reports it as orphaned.

Pulumi takes "a real language" the other way across the boundary: the program
runs against the live engine, resources register over RPC, and `apply()`
callbacks run mid-deploy. Zap's TypeScript emits data and stops.

Scope differs more than model: both are cloud-resource tools with provider
ecosystems. Zap converges the inside of a machine and has no providers. Pair
them: OpenTofu for the droplet and DNS, Zap for what's on the droplet.

**Reach for OpenTofu, Terraform, or Pulumi** for cloud infrastructure, for a
removed-means-destroyed model, or for mature team workflows around state.

### Versus NixOS

The nearest philosophical kin: both make the declaration deterministic. Nix
makes purity a precondition: builds are sandboxed, the whole system is a
function of a pinned expression, and you adopt the store and the language
wholesale to get reproducibility and atomic rollback. The system closure is a
more complete inert artifact than Zap's declaration, and `nixos-rebuild build`,
`dry-activate`, and `nix store diff-closures` let you inspect it before
switching. deploy-rs adds a magic rollback over SSH; nixos-anywhere installs a
machine from nothing.

The difference is prevention versus measurement. Nix prevents drift in what it
owns and is silent about the rest (`/var`, database contents, mutable users);
activation reasserts without reporting. Zap reads and reports drift on every
run, including the security controls, and repairs it. You keep your distro and
your package manager; you give up atomic generations and whole-system rollback.
Guix System is the same model in Scheme; image-based systems (bootc, Fedora
CoreOS, systemd-sysext) are the other prevention answer: don't converge,
replace.

**Reach for NixOS** for whole-system reproducibility and atomic rollback, if
you're willing to adopt the model end to end.

### Versus Puppet, Chef, and Salt

The same convergence model, a different operational one: agents that pull and
converge continuously, usually against a server, with mature resource models and
fleet tooling. All three run masterless too.

Puppet deserves specific credit: it compiles a **catalog**, an inert JSON
resource graph, before applying, and the catalog can be compiled without
applying and diffed. The contrast with Zap is that the catalog's inputs include
facts gathered from the node, which is exactly the host-reactivity Zap declines
to model ([below](#how-each-tool-reacts-to-the-host)). Chef's why-run is
best-effort by its own documentation. Salt's `test=True` and
`state.show_highstate` give an inspectable compiled state; `salt-ssh` is
agentless but needs Python on the target unless it ships Salt's bundled runtime
(`--relenv`).

Puppet and Chef have both moved their official builds behind commercial terms,
with community forks (OpenVox, Cinc) carrying the free builds. Salt
is actively released under Broadcom, with many modules moving to community
extensions.

**Reach for one of these** for a large fleet that wants continuous, pull-based
convergence and a deep existing ecosystem.

### Versus Capistrano, Deployer, and Mina

On the `deploy` axis the comparison shifts: this is release push, not
convergence. Capistrano and its kin ship a versioned release into `releases/`
and swap an atomic `current` symlink, the same model Zap's `deploy` uses, with
`keep_releases` (default 5) and a manual `deploy:rollback`. None has a
built-in health gate or automatic rollback; Capistrano usually clones git on the
server, where Zap builds locally and uploads a tarball. Mina generates one bash
script per deploy and prints it with `--simulate`, as Zap's dry run prints its
remote script. Mina is dormant: no release since 1.2.5.

Zap's additions are the drift preflight (the deploy refuses to ship onto a host
whose convergence config has drifted), the automatic rollback on a failed health
gate, and that deploy rides the same engine as convergence.

**Reach for Capistrano or Deployer** for a mature multi-host release tool with
a plugin ecosystem in the Ruby or PHP world.

### Versus plain shell and cloud-init

The honest baseline: a `setup.sh`, a `Makefile`, a cloud-init file. These are
imperative bootstrap: top to bottom, no idempotency guarantee, no notion of
current state, no dry run, and cloud-init runs most modules once per instance
rather than as a loop. Zap's value over this baseline is exactly what
convergence buys: skip what's done, re-run safely, preview by default, report
after.

**Reach for plain shell** when the task is one-shot, tiny, or so bespoke that a
resource model is more ceremony than it saves.

### Personal machines: mise, chezmoi, home-manager, Brewfile

Zap also sets up a developer's own machine: build tools, a terminal, dotfiles,
packages. The dedicated tools are better at their one job: mise pins tool
versions with a lockfile, chezmoi diffs and templates dotfiles across machines
and supports macOS and Windows, home-manager brings the Nix model to a user's
environment, `brew bundle` declares macOS packages. Zap's
case is one model for the laptop and the servers, with the same `file`, `pkg`,
`build`, and `script` resources, and the same dry run. It doesn't run on macOS.

## How each tool reacts to the host

Zap's declaration is sealed before the machine is touched: the config runs with
no network and no environment, and detection then decides only which declared
changes run. That is why there's no state file, why the plan has a stable hash a
wetrun can be bound to, and why secrets stay inert until use. It splits
"reacting to what's on the host" into three cases:

1. **Detection: gating a declared action on observed state** ("install only if
   missing", "restart only if the config changed"). This is the convergence
   loop itself, plus a `script`'s `check`, `verify` assertions, and triggers.
   Under convergence you don't write "if X, do Y" when Y is idempotent; you
   declare Y and detection skips it.
2. **Derivation: desired state computed from host facts** ("swap is twice the
   detected RAM", "apt on Debian, apk on Alpine"). Terraform does this with
   `data` sources, Puppet and pyinfra with facts, cdist with explorers. Zap
   doesn't read the target during eval; a `script` that computes on the target
   covers these cases.
3. **Mid-run reactivity: decisions from results a prior step produced.** That is
   orchestration (Ansible's `when:` over run-updated facts, a shell script), and
   Zap doesn't do it. Put that logic inside one `script`, or compose Zap with a
   tool built for it.

A `script`'s `run` is arbitrary shell, so the cost is legibility, never
capability. Two caveats: on a local target the config runs on the machine it
describes, so it _could_ read host state at eval time (outside the model, not
prevented); and determinism is by construction for the common sources (the
clock and randomness throw, the time zone and locale are fixed) rather than
proven, where Nix's sandboxed evaluation is the stronger claim.

## Also in the space

**cdist**: agentless SSH push, type-based, generates shell from explorers run on
the target; the closest historical kin, now low-activity. **mgmt**: a
declarative, event-driven engine with a real-time graph that converges
continuously, Zap's polar opposite on timing. **Fabric**, **Rex**, **Puppet
Bolt** / **OpenBolt**: imperative remote task runners. **Kubernetes**: the purest
convergence model there is, continuous reconcilers over etcd, and for a handful
of VPSes the cost is the cluster itself. **Dagger**: a CI/CD pipeline engine, not
a host tool; Zap isn't a CI engine.

## At a glance

One table per axis. Zap's cells are exact; the others are our best
understanding and are kept general on purpose.

### Model: how each tool decides what to do

| Tool | Control model | Desired state fixed when | Can read the target while deciding? | Plan artifact | Plan binds the apply? |
|---|---|---|---|---|---|
| **Zap** | converge, one-shot | at eval, before contact | no (SSH); possible but outside the model (local) | changeset with a blake3 hash | **yes**: a wetrun must match the reviewed hash |
| Ansible | ordered idempotent tasks | at run time, per task | yes (facts, `register`) | none; `--check` simulates | n/a |
| pyinfra | ordered operations over facts | after fact gathering, before execution | yes (facts) | the change summary before the prompt | no |
| Terraform / OpenTofu | converge, graph | plan time | yes (`data` sources) | saved plan file; JSON via `show -json` | **yes**: `apply <planfile>` refuses a stale plan |
| Pulumi | converge, live program | during the update | yes | preview; saved update plans (experimental) | experimental |
| Puppet | converge, graph | catalog compile | yes (node facts) | **catalog** (JSON), compilable without applying | the agent applies the catalog |
| Chef | converge, ordered resources | compile phase on the node | yes (Ohai, arbitrary Ruby) | none; why-run is best-effort | n/a |
| Salt | converge, requisites | render time | yes (grains, pillar) | highstate data (`show_highstate`) | no |
| NixOS | build then activate | eval time, pure with flakes | no | the system closure, a hashed store path | **yes**: you activate the closure you built |
| cdist | converge, types to shell | after explorers run | yes (explorers) | generated shell (`-n`) | no |
| Kubernetes | continuous reconcile | on API write | n/a | `kubectl diff`, server-side dry run | no |
| Capistrano / Deployer / Mina | release push, procedure | run time | yes | none (Deployer `--plan` lists tasks; Mina `--simulate` prints the script) | n/a |
| Kamal | container release push | run time | n/a | none | n/a |
| Compose / Dokku / Coolify | container apps | on deploy | n/a | none | n/a |

### Operations: what you run and where

| Tool | Operator machine needs | Target needs | Server or state backend | State of record | Reaches the target by | Many hosts |
|---|---|---|---|---|---|---|
| **Zap** | one binary plus **fgro** (Gro's runtime), `ssh` | `sshd`, POSIX shell, `sudo` | none | the live machine, plus `zap.lock` for pins | SSH, or local | one host per config, resources in order |
| Ansible | Python | SSH plus **Python** (except `raw`) | none (AWX optional) | the machine | SSH; `ansible-pull` | yes, inventory, parallel forks |
| pyinfra | Python | SSH plus shell | none | the machine | SSH, local, Docker | yes, parallel |
| Terraform / OpenTofu | one binary plus providers | n/a (APIs) | local state file by default; remote backend with locking for teams | the state file | provider APIs | n/a: resources, not hosts |
| Pulumi | binary plus a language runtime | n/a | Pulumi Cloud by default, or self-managed | the state backend | provider APIs | n/a |
| Puppet / OpenVox | server, or `puppet apply` | agent with bundled Ruby | server plus PuppetDB, or masterless | the machine, plus catalogs and reports | agent pull every 30 min | yes, fleet scale |
| Chef / Cinc | server, or local mode | agent with bundled Ruby | Chef Infra Server (the open-source server is end-of-life; Chef 360 or the Cinc Server fork) | the machine plus node objects | agent pull | yes |
| Salt | master | minion, or `salt-ssh` with Python on the target | master, or masterless | the machine plus job cache | ZeroMQ or SSH | yes |
| NixOS | Nix | NixOS | none | the Nix store and generations | local, `--target-host`, deploy-rs, colmena | via deploy-rs or colmena |
| cdist | Python | SSH plus shell | none | the machine | SSH | yes, parallel |
| Kubernetes | `kubectl` | a cluster | etcd | etcd | API server | yes |
| Capistrano / Deployer / Mina | Ruby or PHP | SSH, git for Capistrano | none | `releases/` on the host | SSH | yes |
| Kamal | Ruby, or its Docker image | SSH plus Docker (installed by `kamal setup`) | a container registry | containers on the host | SSH plus registry | yes, rolling |
| Coolify / CapRover | a browser | Docker plus their control plane on a server | on-server control plane | its control plane | its UI or agent | yes |
| Dokku | git | Docker plus Dokku | on the server | Dokku's config | `git push` | one server (schedulers for more) |

### Safety: what protects you from a bad run

| Tool | Dry-run posture | Dry-run fidelity | A read that fails | After acting | Secrets at rest | Rollback |
|---|---|---|---|---|---|---|
| **Zap** | **default**; `--wetrun` to act; on a terminal with nothing reviewed, **asks** for the start of the `plan_hash` (no flag answers it) | full detection, nothing executes | **held**: out of the plan, exit 1 | re-detects; anything not converged is `RESIDUAL`, exit 1 | none stored; references resolved at apply and masked | deploy: previous release, health gate; convergence: re-apply the old config |
| Ansible | opt-in `--check` (+ `--diff`) | per module; `command`/`shell` need `creates`/`removes` | task error or unreachable | none built in (`assert` tasks) | Ansible Vault, encrypted in the repo | none built in |
| pyinfra | shows changes, then **prompts** (`-y` skips); `--dry` exits after | fact-based, may not include every change | error | none | user-managed | none |
| Terraform / OpenTofu | plan, then **prompt** (`-auto-approve` skips) | high; "known after apply" unknowns | refresh fails the plan | next plan shows drift | plaintext in state (OpenTofu 1.7+ can encrypt; Terraform ephemeral values from 1.10) | re-apply the old config |
| Pulumi | preview, then **prompt** (`--yes` skips) | high | error | none | encrypted per stack | none built in |
| Puppet | opt-in `--noop` | high for native types; `exec` guards run, commands don't | resource fails, run continues | next run | Hiera eyaml and the like | re-apply the old catalog |
| Chef | opt-in `--why-run` | best-effort, with assumptions; Chef's own blog calls it harmful | error | next run | encrypted data bags, Vault | none |
| Salt | opt-in `test=True` | per module | error | none | pillar, GPG renderer | none |
| NixOS | `build` or `dry-activate` before `switch` | the build is exact; activation partly | the build fails before touching the system | n/a | world-readable store unless agenix or sops-nix | **atomic generations, boot menu** |
| Kubernetes | `--dry-run=server`, `kubectl diff` | high | reconciler retries | continuous | base64 by default; encryption at rest opt-in | `rollout undo` |
| Capistrano / Mina | Mina `--simulate`; Capistrano none | printed script | error | none | `linked_files` | `deploy:rollback`, manual |
| Kamal | none | n/a | error | kamal-proxy health-checks the new container **before** switching | `.kamal/secrets` with password-manager adapters | `kamal rollback <version>` |

### Scope and maturity

| Tool | Primary scope | Authoring | Config typed? | OS coverage | Maturity |
|---|---|---|---|---|---|
| **Zap** | inside a Linux box, app deploy, dev tools | TypeScript pure function to JSON | yes: TS types plus a strict schema at plan | Debian/Ubuntu, Alpine | **pre-alpha, one maintainer, small fixed resource set, no plugins** |
| Ansible | machine config and ad-hoc ops | YAML plus Jinja2 | lint only | very broad, Windows and network devices included | huge; Galaxy collections |
| pyinfra | machine config | Python | Python typing | broad POSIX | small to medium; active (3.x) |
| Terraform / OpenTofu | cloud resources | HCL | schema-validated | n/a | huge; provider registry. Terraform is BUSL-licensed from 1.6; OpenTofu is the MPL fork |
| Pulumi | cloud resources | TS, Python, Go, C#, Java, YAML | yes | n/a | large |
| Puppet / Chef | fleet machine config | Puppet DSL, Ruby | partial | broad, Windows included | large and mature; both moved their official builds behind commercial terms, with community forks (OpenVox, Cinc) |
| Salt | config, remote execution, events | YAML plus Jinja and other renderers | no | broad | large; actively released under Broadcom, many modules moving to extensions |
| NixOS | the whole OS | Nix | module system checks at eval | NixOS (nix-darwin for macOS) | large; steep curve |
| Kamal | container app deploy | YAML | no | any Docker host | medium; 37signals-backed |
| Compose / Dokku / Coolify | container apps | YAML or a UI | no | any Docker host | large |
| mise / chezmoi / home-manager | dev tools, dotfiles | TOML, templates, Nix | no | Linux and macOS (chezmoi: Windows too) | medium to large |
