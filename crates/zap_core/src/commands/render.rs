//! The plan renders the commands share: a change and its steps, the declared side of a
//! resource, the machine and target lines, the reference values a plan was computed
//! with, and the plan's address.

use std::collections::BTreeMap;

use std::fmt::Write as _;

use zap_types::last_run::ReportVar;
use zap_types::plan::{
    Change, ChangeAction, LocalAccount, Machine, Plan, PlanStep, ProducerSummary, PutSource,
    PutStep, ReferenceValue, Trigger,
};
use zap_types::scalar::{ContentHash, EnvVarName};
use zap_types::schema::{
    BuildSource, DeclaredPackageCheck, ExtractMode, FileContent, RemoteAuth, Resource, ResourceId,
    ResourceKind, SourceVerify, Target,
};
use zap_types::text::Text;
use zap_types::var_ref::{self, Segment};

use crate::error::{Error, Result};
use crate::escape::{escape_join, escape_line, render_block};

use super::PlanAddress;

/// The trigger line under a service change: what fired it this run, and whether an
/// earlier apply left it pending.
pub(super) fn render_trigger(out: &mut String, trigger: &Trigger) {
    let kind = trigger.kind.as_str();
    let _ = match (trigger.sources.is_empty(), trigger.pending) {
        (false, false) => writeln!(out, "      (triggered {kind})"),
        (false, true) => writeln!(
            out,
            "      (triggered {kind}, also pending from an earlier apply)"
        ),
        (true, _) => writeln!(out, "      (pending {kind} from an earlier apply)"),
    };
}

/// Render one planned `Change`: the shared `[+/~] id (kind)` header, what the change
/// declares ([`render_declared`]), the file zap installs ahead of its steps
/// ([`render_native_puts`]), and its step lines (`>` an executable command, `#` a
/// preview note the executor firms up, `=` an operation zap carries out through a script
/// of its own), with the trigger line ([`render_trigger`]) under the header of a
/// change a trigger fired or an earlier apply left pending. The `plan` render and the
/// `apply` dry-run preview share this, so each prints what fired a change and whether
/// it was pending — both in the plan's hash.
pub(super) fn render_change(out: &mut String, change: &Change) {
    render_change_header(out, change);
    if let Some(trigger) = &change.trigger {
        render_trigger(out, trigger);
    }
    render_declared(out, &change.desired);
    render_native_puts(out, change);
    render_steps(out, change);
}

/// The `=` line of a file zap installs for a change ahead of its steps, which no step
/// holds: an `apt_repo`'s signing key, at its key path, the bytes its `pin:` names.
pub(super) fn render_native_puts(out: &mut String, change: &Change) {
    if let ResourceKind::AptRepo(repo) = &change.desired.kind {
        let (key_path, _) = zap_types::observe::apt_repo::paths(&change.resource_id.0, repo);
        let _ = writeln!(
            out,
            "      = put {}  (mode 644, owner root:root, as root)",
            escape_line(&key_path)
        );
    }
}

/// A change's `[+/~] id (kind)` line.
pub(super) fn render_change_header(out: &mut String, change: &Change) {
    let symbol = match change.action {
        ChangeAction::Create => '+',
        ChangeAction::Update => '~',
    };
    let _ = writeln!(
        out,
        "  [{symbol}] {}  ({})",
        escape_line(&change.resource_id.0),
        change.desired.kind().as_str()
    );
}

/// A change's step lines: a block under `>` for a command, under `#` for a note, and
/// for a typed step a `=` line that says what it does ([`render_typed_step`]).
pub(super) fn render_steps(out: &mut String, change: &Change) {
    for step in &change.steps {
        match step {
            PlanStep::Run(cmd) => render_block(out, "      > ", cmd),
            PlanStep::Note(note) => render_block(out, "      # ", note),
            PlanStep::Put(_)
            | PlanStep::Dir(_)
            | PlanStep::PgHbaRule(_)
            | PlanStep::Installer(_)
            | PlanStep::SwapCheck(_) => {
                render_typed_step(out, step);
            }
        }
    }
}

/// A typed step: `= <what>  (<details>)` from the step's own summary — the words a
/// failure of it is named by — and, for a put, where its content comes from.
///
/// - Text the plan holds: its length and the head of its SHA-512 (the digest the put
///   verifies) join the details, and the text follows whole under `text:`, less the
///   newline it ends with (a text with none says so). It is what the change installs —
///   a key, a sudo grant, a ruleset — and holds no reference.
/// - A command's output: `from:` says in words which of zap's commands prints it and
///   what skips the step, and `line:` is the text of the config's that command is given
///   — an apt source line, an fstab entry — exactly as the target's shell receives it,
///   before anything in it expands there.
///
/// An installer's step is its `=` line alone: the URL the script is fetched from and
/// the shell it is piped to, each as declared.
///
/// Never the shell text the step runs: the summary names the operation instead.
/// Each line under the `=` is a block led past its column, so no line of a text
/// stands where one of zap's own does.
fn render_typed_step(out: &mut String, step: &PlanStep) {
    let Some(summary) = step.summary() else {
        return;
    };
    let text = match step {
        PlanStep::Put(PutStep {
            source: PutSource::Text(text),
            ..
        }) => Some(text.content.as_str()),
        _ => None,
    };
    let held = text.map_or_else(String::new, |text| {
        let newline = if text.ends_with('\n') {
            ""
        } else {
            ", no final newline"
        };
        format!("; {}{newline}", content_digest(text))
    });
    let _ = writeln!(
        out,
        "      = {}  ({}{held})",
        escape_line(&summary.what),
        escape_line(&summary.details),
    );
    let PlanStep::Put(put) = step else {
        return;
    };
    match &put.source {
        PutSource::Text(text) => {
            let shown = text.content.strip_suffix('\n').unwrap_or(&text.content);
            render_block(out, "          text: ", shown);
        }
        PutSource::Command(command) => {
            let ProducerSummary { from, line } = command.producer.summary();
            render_block(out, "          from: ", &from);
            if let Some(line) = line {
                render_block(out, "          line: ", &line);
            }
        }
    }
}

/// A text by its length and the head of its SHA-512: enough to tell two texts apart,
/// and to check one against a file (`sha512sum`) when the text is what the file holds.
/// A template's descriptor digests the template as written, before its variables are
/// filled, so it is not the digest of the file it renders to.
fn content_digest(text: &str) -> String {
    let digest = crate::digest::sha512_hex(text.as_bytes());
    format!("{} bytes, sha512 {}…", text.len(), &digest[..16])
}

/// The lines under a change's header that say what it declares, read from its desired
/// resource: what a reviewer needs to know the change by that its step lines don't say.
///
/// First its `name:`, when it declares one: the label is in the change, so in the
/// plan's hash, and is printed for that. Never on the header line, where a label could
/// make the header read as another; here it is one escaped line after a fixed key.
/// Then what its kind declares:
///
/// - `file`: `path:`, the `mode:` / `owner:` / `group:` it declares, its `content:`
///   ([`render_content`]), its `validate:` command, and the services it `triggers:`.
/// - `directory`: `path:` and its `mode:` / `owner:` / `group:`.
/// - `link`: `path:` and `to:`, where it points.
/// - `script`: `cwd:`, each `env:` variable, and `check:` — the command detection runs.
/// - `build`: its `source:` ([`render_fetched`]), how the source is `verify:`ed, the
///   `output:` it must leave, then `cwd:` and `env:`. A `build` with no `cwd` runs in
///   its extracted source directory, which has no name until it runs.
/// - `apt_repo`: its signing `key:` ([`render_fetched`]); the key's install and its
///   steps say the rest.
/// - `package`, `installer`: `check:`, when one is declared.
/// - `service`: the resources it restarts or reloads on (`restart_on:`, `reload_on:`).
/// - `swap`: its `size:`, which a swap file already active allocates nothing by, so no
///   step of its change says it.
/// - `pipeline`: the `max_concurrency:` it declares, then each step in declared order,
///   as `step:` and its `id`, then `step name:` and its `name` when it declares one.
///   The step's `run` is its `>` line below, in the same order. Each is its own line,
///   so no id can make a name read as part of it.
///
/// Everything is the declared text: a reference stays inert,
/// never the value it resolves to, and a `~` stays a `~`. Nothing for a kind whose steps
/// already say what it is.
///
/// Each line leads at the column a step's `>` does, which no continuation line of a
/// multi-line step or value reaches ([`render_block`] indents those past it), so a
/// command's text can't stand in for one.
pub(super) fn render_declared(out: &mut String, resource: &Resource) {
    if let Some(name) = &resource.name {
        let _ = writeln!(out, "      name: {}", escape_line(name));
    }
    let line = |out: &mut String, key: &str, value: &str| {
        render_block(out, &format!("      {key}: "), value);
    };
    let optional = |out: &mut String, key: &str, value: Option<&str>| {
        if let Some(value) = value {
            line(out, key, value);
        }
    };
    let ids = |out: &mut String, key: &str, ids: Option<&Vec<ResourceId>>| {
        if let Some(ids) = ids.filter(|ids| !ids.is_empty()) {
            let _ = writeln!(
                out,
                "      {key}: {}",
                escape_join(ids.iter().map(|id| &id.0), ", ")
            );
        }
    };
    let run_context =
        |out: &mut String, cwd: Option<&str>, env: Option<&BTreeMap<EnvVarName, Text>>| {
            optional(out, "cwd", cwd);
            for (name, value) in env.into_iter().flatten() {
                let lead = format!("      env: {}=", escape_line(name.as_str()));
                render_block(out, &lead, value);
            }
        };
    match &resource.kind {
        ResourceKind::File(file) => {
            line(out, "path", &file.path);
            optional(out, "mode", file.mode.as_deref());
            optional(out, "owner", file.owner.as_deref());
            optional(out, "group", file.group.as_deref());
            render_content(out, &file.content);
            optional(out, "validate", file.validate.as_deref());
            ids(out, "triggers", file.triggers.as_ref());
        }
        ResourceKind::Directory(directory) => {
            line(out, "path", &directory.path);
            optional(out, "mode", directory.mode.as_deref());
            optional(out, "owner", directory.owner.as_deref());
            optional(out, "group", directory.group.as_deref());
        }
        ResourceKind::Link(link) => {
            line(out, "path", &link.path);
            line(out, "to", &link.target);
        }
        ResourceKind::Script(script) => {
            run_context(out, script.cwd.as_deref(), script.env.as_ref());
            line(out, "check", &script.check);
        }
        ResourceKind::Build(build) => {
            let BuildSource::Remote(source) = &build.source;
            render_fetched(
                out,
                "source",
                &source.url,
                source.extract,
                source.blake3.as_ref(),
                source.auth.as_ref(),
            );
            if let Some(SourceVerify::Minisign(minisign)) = &source.verify {
                line(out, "verify", &format!("minisign {}", minisign.public_key));
                optional(out, "signature", minisign.signature_url.as_deref());
            }
            line(out, "output", &build.output);
            run_context(out, build.cwd.as_deref(), build.env.as_ref());
        }
        ResourceKind::Package(package) => optional(
            out,
            "check",
            package
                .check
                .as_ref()
                .map(DeclaredPackageCheck::as_declared),
        ),
        ResourceKind::Installer(installer) => line(out, "check", &installer.check),
        ResourceKind::Service(service) => {
            ids(out, "restart_on", service.restart_on.as_ref());
            ids(out, "reload_on", service.reload_on.as_ref());
        }
        ResourceKind::AptRepo(repo) => {
            render_fetched(
                out,
                "key",
                &repo.key_url,
                ExtractMode::None,
                repo.key_blake3.as_ref(),
                None,
            );
        }
        ResourceKind::Pipeline(pipeline) => {
            if let Some(max) = pipeline.max_concurrency {
                let _ = writeln!(out, "      max_concurrency: {max}");
            }
            for step in &pipeline.steps {
                let _ = writeln!(out, "      step: {}", escape_line(&step.id));
                if let Some(name) = &step.name {
                    let _ = writeln!(out, "      step name: {}", escape_line(name));
                }
            }
        }
        ResourceKind::Swap(swap) => line(out, "size", &swap.size),
        ResourceKind::User(_)
        | ResourceKind::Database(_)
        | ResourceKind::Firewall(_)
        | ResourceKind::Verify(_) => {}
    }
}

/// A `file`'s `content:` line: what its content is, without the content.
///
/// - inline: its length and the head of the SHA-512 of the declared text — enough to
///   tell two contents apart and, for content with no reference, to check it against
///   the file (`sha512sum`). The text
///   is what the config wrote: a reference in it is hashed as the reference.
/// - template: the same for the template text, then its `vars` and the `kinds` they
///   must render to as declared, each one line of JSON.
/// - source: the path it is copied from.
/// - remote: [`render_fetched`].
fn render_content(out: &mut String, content: &FileContent) {
    let digest = content_digest;
    match content {
        FileContent::Inline { content } => {
            let _ = writeln!(out, "      content: inline ({})", digest(content));
        }
        FileContent::Template(template) => {
            let _ = write!(
                out,
                "      content: template ({})",
                digest(&template.template)
            );
            if !template.vars.is_empty() {
                let vars = serde_json::to_string(&template.vars)
                    .unwrap_or_else(|error| format!("(unrenderable: {error})"));
                let _ = write!(out, ", vars {}", escape_line(&vars));
            }
            if !template.kinds.is_empty() {
                let kinds = serde_json::to_string(&template.kinds)
                    .unwrap_or_else(|error| format!("(unrenderable: {error})"));
                let _ = write!(out, ", kinds {}", escape_line(&kinds));
            }
            let _ = writeln!(out);
        }
        FileContent::Source { path } => {
            render_block(out, "      content: copied from ", path);
        }
        FileContent::Remote(remote) => render_fetched(
            out,
            "content",
            &remote.url,
            remote.extract,
            remote.blake3.as_ref(),
            remote.auth.as_ref(),
        ),
    }
}

/// The lines for bytes a change fetches — a `remote` file's content, a `build`'s source,
/// an `apt_repo`'s key:
/// the url as declared under `key`, how the archive is unpacked (`extract:`, when it
/// is), the `pin:` its bytes must have, and the `auth:` it is fetched with.
///
/// The pin is printed whole: it is what names the bytes. Of a credential only the
/// references are printed — `{env:NAME}`, which variable the token comes from — and any
/// literal text in it as `(literal)`: a token written into the config is a secret zap
/// has no name for.
fn render_fetched(
    out: &mut String,
    key: &str,
    url: &str,
    extract: ExtractMode,
    pin: Option<&ContentHash>,
    auth: Option<&RemoteAuth>,
) {
    render_block(out, &format!("      {key}: fetched from "), url);
    if extract.is_tar() {
        let _ = match extract.strip_components() {
            0 => writeln!(out, "      extract: {}", extract.format_str()),
            strip => writeln!(
                out,
                "      extract: {}, strip {strip}",
                extract.format_str()
            ),
        };
    }
    let _ = match pin {
        Some(pin) => writeln!(out, "      pin: blake3 {}", escape_line(pin.as_str())),
        None => writeln!(out, "      pin: none yet (tracked in zap.lock)"),
    };
    if let Some(RemoteAuth::Bearer { token }) = auth {
        let shown: String = token
            .pieces()
            .map(|segment| match segment {
                Segment::Text(_) => "(literal)".to_owned(),
                Segment::Ref(name) => var_ref::shown(&escape_line(name)),
            })
            .collect();
        let _ = writeln!(out, "      auth: bearer {shown}");
    }
}

/// Target location label shared by the plan / detect / status / apply renders.
pub(super) fn target_location(target: &Target) -> String {
    if target.is_local() {
        "local".to_owned()
    } else {
        target.host().map_or("remote", Text::as_inert).to_owned()
    }
}

/// The lines under a plan's header that name the machine it is for, wherever the header's
/// declared target doesn't already: the resolved host when it isn't the declared text
/// (`declared`, a [`target_location`]), and the connecting user — or that the plan
/// names none (`NO_USER`). A local plan names the user zap runs as and the home its
/// paths' `~` resolves to — or that it has none (`NO_HOME`).
pub(super) fn render_machine(out: &mut String, declared: &str, machine: &Machine) {
    let (host, user) = match machine {
        Machine::Local(LocalAccount { user, home }) => {
            let _ = writeln!(out, "  user: {}", escape_line(user));
            let _ = match home {
                Some(home) => writeln!(out, "  home: {}", escape_line(home)),
                None => writeln!(out, "  home: {NO_HOME}"),
            };
            return;
        }
        Machine::Remote { host, user } => (host, user),
    };
    if host != declared {
        let _ = writeln!(out, "  host: {}", escape_line(host));
    }
    let _ = match user {
        Some(user) => writeln!(out, "  user: {}", escape_line(user)),
        None => writeln!(out, "  user: {NO_USER}"),
    };
}

/// The `target:` line of a preview: the declared target as one line of JSON, the shape
/// the config wrote it in — `{"local":true}` for the machine zap runs on. A reference in
/// it is its typed wire form, `{"$env":"NAME"}`; what it resolves to is on the `host:` /
/// `user:` lines.
///
/// A plan's hash covers its whole declared target — the managers, the port, the key
/// path, the home, both users — so a preview prints all of it.
pub(super) fn render_target(out: &mut String, target: &Target) {
    let target =
        serde_json::to_string(target).unwrap_or_else(|error| format!("(unrenderable: {error})"));
    let _ = writeln!(out, "  target: {}", escape_line(&target));
}

/// The lines under a convergence plan's header that say what it is for: the machine
/// ([`render_machine`]), the declared target ([`render_target`]), then what the
/// references its changes use resolve to ([`render_references`]). With the header and
/// the changes under them these put the plan's `target`, `machine` and `references` on
/// screen.
pub(super) fn render_plan_subject(out: &mut String, declared: &str, plan: &Plan) {
    render_machine(out, declared, &plan.machine);
    render_target(out, &plan.target);
    render_references(out, &plan.references);
}

/// The most characters of a reference's value a preview prints.
///
/// A value is one line of a preview, there to be read. The hash covers the whole of
/// it, so past this bound the line says how much more there is and closes with a short
/// digest of the whole value: two plans that differ only beyond the bound still read
/// differently.
pub const REFERENCE_VALUE_SHOWN: usize = 200;

/// The `references:` block of a preview: what each reference a plan uses resolved to
/// when the plan was computed, one line a name, in name order. Nothing for a plan that
/// uses none.
///
/// A value follows `NAME = `, escaped onto one line like every printed string — a
/// registered secret inside it is already its masking token ([`ReferenceValue::Value`])
/// — and cut at [`REFERENCE_VALUE_SHOWN`] characters. A secret and an unset variable
/// are said in words after `NAME is `, which no value's line begins with, so a value
/// can't pass for either. The changes below keep naming a reference as `{env:NAME}`:
/// this block is where its value is read.
pub(super) fn render_references(
    out: &mut String,
    references: &BTreeMap<EnvVarName, ReferenceValue>,
) {
    if references.is_empty() {
        return;
    }
    let _ = writeln!(out, "  references:");
    for (name, value) in references {
        let name = name.as_str();
        let _ = match value {
            ReferenceValue::Value(value) => {
                writeln!(out, "    {name} = {}", shown_reference_value(value))
            }
            ReferenceValue::Secret => writeln!(
                out,
                "    {name} is a secret: its value is not shown, and no part of it is in \
                 the plan or its hash"
            ),
            ReferenceValue::Unset => writeln!(
                out,
                "    {name} is unset or empty: a wetrun stops before any change until it \
                 is set"
            ),
        };
    }
}

/// A reference's value as [`render_references`] prints it: escaped, and past
/// [`REFERENCE_VALUE_SHOWN`] characters cut, with what was left out counted and the
/// whole value's short digest.
fn shown_reference_value(value: &str) -> String {
    let total = value.chars().count();
    if total <= REFERENCE_VALUE_SHOWN {
        return escape_line(value).into_owned();
    }
    let head: String = value.chars().take(REFERENCE_VALUE_SHOWN).collect();
    let digest = blake3::hash(value.as_bytes()).to_hex();
    format!(
        "{} … (+{} more character(s); the whole value's blake3 begins {})",
        escape_line(&head),
        total - REFERENCE_VALUE_SHOWN,
        &digest.as_str()[..12]
    )
}

/// The references among those `plan` recorded that no longer resolve, through `var`,
/// to what it recorded — by name.
///
pub(super) fn moved_references(plan: &Plan, var: &dyn Fn(&str) -> ReportVar) -> Vec<String> {
    plan.references
        .iter()
        .filter(|(name, recorded)| ReferenceValue::of(var(name.as_str())) != **recorded)
        .map(|(name, _)| name.as_str().to_owned())
        .collect()
}

/// A wetrun's last check before its first change: every reference `plan` recorded
/// still resolves, through `var`, to the value it recorded ([`moved_references`]).
///
/// A defensive check. A wetrun plans and executes in one process and one environment,
/// which is read at each resolve and which nothing in zap writes once `--env-file` is
/// loaded, so today no run can fail it: the values a plan recorded are the values its
/// steps resolve to. It would fire if that stopped holding — a plan handed to the
/// executor from another process or another moment (a saved plan, a daemon), a resolver
/// with a source that can change under a run (a secret store, a file re-read), or an
/// environment zap itself rewrote between the gate and the steps. Then the review gate's
/// claim, that what runs is the plan whose hash was reviewed, would rest on this line.
///
/// # Errors
/// [`Error::WetrunRefused`] naming each reference that moved; nothing has run.
pub(super) fn check_references(plan: &Plan, var: &dyn Fn(&str) -> ReportVar) -> Result<()> {
    let moved = moved_references(plan, var);
    if moved.is_empty() {
        return Ok(());
    }
    Err(Error::WetrunRefused(format!(
        "the environment changed while this run was in progress — nothing ran: {} no \
         longer resolve(s) to the value the plan recorded; re-run",
        moved.join(", ")
    )))
}

/// How a preview names the connecting user of a remote plan that has none: the target
/// declares no user. The run then connects as whichever user the operator's own `ssh`
/// picks, which the plan can't name. (A user that is declared and resolves empty is
/// refused before any plan: `no_user_message`.)
pub(super) const NO_USER: &str = "(none — ssh chooses)";

/// How a preview names the home of a local plan that has none: `HOME` is unset or empty,
/// so a path that references the home is refused.
const NO_HOME: &str = "(none — HOME is unset)";

/// The foot of a plan that names no one machine, in place of its `plan_hash:` line: why
/// it has none, and what follows.
pub(super) fn render_unbindable(out: &mut String, reason: &str) {
    let _ = writeln!(
        out,
        "  (a wetrun of this config is refused, so this plan has no plan_hash and is not \
         recorded as a preview)"
    );
    render_block(out, "  UNBINDABLE — ", reason);
}

/// The note that a pass left no last-run report, and why
/// ([`unidentified_host_message`]). No-op when it recorded one.
///
/// [`unidentified_host_message`]: super::unidentified_host_message
pub(super) fn render_unrecorded(out: &mut String, reason: Option<&str>) {
    if let Some(reason) = reason {
        render_block(
            out,
            "  UNRECORDED — no last run is kept for this target, so `zap status` has none \
             to show: ",
            reason,
        );
    }
}

/// A plan's last line: its `plan_hash:`, or — for a plan with no address — why it has
/// none ([`render_unbindable`]).
pub(super) fn render_address(out: &mut String, address: &PlanAddress) {
    match address {
        PlanAddress::Hash(hash) => {
            let _ = writeln!(out, "plan_hash: {hash}");
        }
        PlanAddress::Unbindable(reason) => render_unbindable(out, reason),
    }
}
