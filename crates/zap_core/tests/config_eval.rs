//! Integration tests for the config eval (`config::eval`), through a real `fgro`.
//!
//! These require `ZAP_FGRO`, an absolute path to an `fgro` build. They check nothing
//! where it's unset, and `required_programs.rs` fails there.

#![allow(clippy::unwrap_used, clippy::expect_used, clippy::panic)]

mod common;
mod scratch;

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use common::{fgro, fgro_available, pinned};
use zap_core::config::eval_cache::observe_and_persist;
use zap_core::config::{
    EvalCacheMode, EvalCacheObservation, eval_cached, eval_config, eval_config_raw,
};
use zap_core::error::Error;
use zap_core::home::eval_cache_dir_for;
use zap_types::schema::PackageManager;
use zap_types::text::Text;

/// Make `dir` a project that links this checkout in as `@fuzdev/zap`, the way a
/// consumer's `npm install` of a path dependency does, so a config there imports the
/// recipes by package name: zap evaluates a config only from its project and the
/// packages the project links.
fn zap_project(dir: &Path) {
    let repo = std::fs::canonicalize(Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")).unwrap();
    std::fs::write(
        dir.join("package.json"),
        r#"{"name":"site","type":"module"}"#,
    )
    .unwrap();
    std::fs::create_dir_all(dir.join("node_modules/@fuzdev")).unwrap();
    std::os::unix::fs::symlink(repo, dir.join("node_modules/@fuzdev/zap")).unwrap();
}

/// Write `body` to `<dir>/zap.ts` and return its path.
fn write_config(dir: &Path, body: &str) -> PathBuf {
    let path = dir.join("zap.ts");
    scratch::write_config(&path, body).unwrap();
    path
}

#[tokio::test]
async fn evaluates_a_minimal_config() {
    if !fgro_available() {
        eprintln!("skipping evaluates_a_minimal_config: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    zap.target({local: true, package_manager: 'apt', service_manager: 'systemd'});
    zap.pkg({id: 'curl', name: 'curl', from: {apt: 'curl'}});
    zap.directory({id: 'devdir', name: 'dev', path: '/home/x/dev'});
    zap.unmask('PUBLIC_THING');
};
",
    );

    let config = eval_config(&path, pinned())
        .await
        .expect("eval should succeed");
    assert!(config.target.is_local());
    assert_eq!(config.target.package_manager, Some(PackageManager::Apt));
    assert_eq!(config.resources.len(), 2);
    let ids: Vec<&str> = config.resources.iter().map(|r| r.id.0.as_str()).collect();
    assert_eq!(ids, ["curl", "devdir"]);
}

#[tokio::test]
async fn preserves_var_references_in_target() {
    if !fgro_available() {
        eprintln!("skipping preserves_var_references_in_target: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    zap.target({
        host: zap.env('DEPLOY_HOST'),
        user: `svc-${zap.env('DEPLOY_USER')}`,
        package_manager: 'apt',
    });
};
",
    );
    let config = eval_config(&path, pinned())
        .await
        .expect("eval should succeed");
    assert!(!config.target.is_local());
    assert_eq!(
        config.target.host().map(Text::as_inert),
        Some(zap_types::var_ref::marker("DEPLOY_HOST").as_str())
    );
    assert_eq!(
        config.target.user().map(Text::as_inert),
        Some(format!("svc-{}", zap_types::var_ref::marker("DEPLOY_USER")).as_str())
    );
}

#[tokio::test]
async fn evaluates_a_config_with_a_relative_import() {
    if !fgro_available() {
        eprintln!("skipping evaluates_a_config_with_a_relative_import: ZAP_FGRO not set");
        return;
    }
    // A sibling helper module — config eval allows unrestricted reads, so a
    // repo-relative import resolves.
    let dir = scratch::tempdir().unwrap();
    std::fs::write(
        dir.path().join("helper.ts"),
        "export const PKG = 'ripgrep';\n",
    )
    .unwrap();
    let path = write_config(
        dir.path(),
        r"
import {PKG} from './helper.ts';
export default (zap) => {
    zap.target({local: true, package_manager: 'apt'});
    zap.pkg({id: PKG, name: PKG, from: {apt: PKG}});
};
",
    );
    let config = eval_config(&path, pinned())
        .await
        .expect("eval with a relative import should succeed");
    assert_eq!(config.resources.len(), 1);
    assert_eq!(config.resources[0].id.0, "ripgrep");
}

#[cfg(unix)]
#[tokio::test]
async fn evaluates_a_config_importing_a_symlinked_dependency() {
    if !fgro_available() {
        eprintln!("skipping evaluates_a_config_importing_a_symlinked_dependency: ZAP_FGRO not set");
        return;
    }
    // A dependency package living OUTSIDE the config dir, symlinked into
    // node_modules the way npm installs a `"../sibling"` path dep — the canonical
    // recipe-import shape: `fgro`'s box admits a package linked into the project. It
    // lives under the build's temp directory, not `/tmp`: a package reached through a
    // directory every user can write is refused.
    let dep = tempfile::tempdir_in(env!("CARGO_TARGET_TMPDIR")).unwrap();
    std::fs::write(
        dep.path().join("package.json"),
        r#"{"name": "@probe/helper", "version": "1.0.0", "type": "module", "exports": {"./util.js": "./util.js"}}"#,
    )
    .unwrap();
    std::fs::write(
        dep.path().join("util.js"),
        "export const PKG = 'ripgrep';\n",
    )
    .unwrap();

    let dir = scratch::tempdir().unwrap();
    std::fs::write(
        dir.path().join("package.json"),
        r#"{"name": "consumer", "type": "module", "dependencies": {"@probe/helper": "*"}}"#,
    )
    .unwrap();
    let scope = dir.path().join("node_modules").join("@probe");
    std::fs::create_dir_all(&scope).unwrap();
    std::os::unix::fs::symlink(dep.path(), scope.join("helper")).unwrap();

    let path = write_config(
        dir.path(),
        r"
import {PKG} from '@probe/helper/util.js';
export default (zap) => {
    zap.target({local: true, package_manager: 'apt'});
    zap.pkg({id: PKG, name: PKG, from: {apt: PKG}});
};
",
    );
    let config = eval_config(&path, pinned())
        .await
        .expect("eval importing a symlinked dependency should succeed");
    assert_eq!(config.resources.len(), 1);
    assert_eq!(config.resources[0].id.0, "ripgrep");
}

/// The ambient sources the wrapper closes, each as a config would reach it: the
/// expression, the name its refusal leads with, and what the refusal says is wrong.
///
/// One row for every entry of the wrapper's tables
/// (`every_closed_source_has_a_row` holds the two together), and rows for the ways
/// around a replaced global that are closed with it: the original reached through a
/// prototype, a `.constructor`, or a clone.
const CLOSED_SOURCES: &[(&str, &str, &str)] = &[
    // The clock.
    ("Date.now()", "Date.now()", CLOCK),
    ("new Date()", "`new Date()`", CLOCK),
    ("Date()", "`Date()`", CLOCK),
    ("Reflect.construct(Date, [])", "`new Date()`", CLOCK),
    (
        "new (Object.getPrototypeOf(new Date(0)).constructor)()",
        "`new Date()`",
        CLOCK,
    ),
    (
        "new (structuredClone(new Date(0)).constructor)()",
        "`new Date()`",
        CLOCK,
    ),
    ("new (class extends Date {})()", "`new Date()`", CLOCK),
    ("(0, eval)('Date.now()')", "Date.now()", CLOCK),
    ("new Function('return new Date()')()", "`new Date()`", CLOCK),
    ("performance.now()", "performance.now()", CLOCK),
    (
        "Object.getPrototypeOf(performance).now.call(performance)",
        "performance.now()",
        CLOCK,
    ),
    ("performance.mark('m')", "performance.mark()", CLOCK),
    ("performance.measure('m')", "performance.measure()", CLOCK),
    ("performance.toJSON()", "performance.toJSON()", CLOCK),
    ("performance.timeOrigin", "performance.timeOrigin", CLOCK),
    ("new PerformanceMark('m')", "`PerformanceMark`", CLOCK),
    (
        "new File([], 'f').lastModified",
        "File.prototype.lastModified",
        CLOCK,
    ),
    ("Temporal.Now.instant()", "Temporal.Now.instant()", CLOCK),
    (
        "Temporal.Now.plainDateTimeISO()",
        "Temporal.Now.plainDateTimeISO()",
        CLOCK,
    ),
    (
        "Temporal.Now.zonedDateTimeISO()",
        "Temporal.Now.zonedDateTimeISO()",
        CLOCK,
    ),
    (
        "Temporal.Now.plainDateISO()",
        "Temporal.Now.plainDateISO()",
        CLOCK,
    ),
    (
        "Temporal.Now.plainTimeISO()",
        "Temporal.Now.plainTimeISO()",
        CLOCK,
    ),
    ("process.hrtime()", "process.hrtime()", CLOCK),
    ("process.hrtime.bigint()", "process.hrtime.bigint()", CLOCK),
    ("process.uptime()", "process.uptime()", CLOCK),
    (
        "new Intl.DateTimeFormat('en', {timeZone: 'UTC'}).format()",
        "`Intl.DateTimeFormat` `format()` with no date",
        CLOCK,
    ),
    (
        "new Intl.DateTimeFormat('en', {timeZone: 'UTC'}).formatToParts()",
        "`Intl.DateTimeFormat` `formatToParts()` with no date",
        CLOCK,
    ),
    // Randomness.
    ("Math.random()", "Math.random()", RANDOM),
    (
        "crypto.getRandomValues(new Uint8Array(4))",
        "crypto.getRandomValues()",
        RANDOM,
    ),
    (
        "Object.getPrototypeOf(crypto).getRandomValues.call(crypto, new Uint8Array(4))",
        "crypto.getRandomValues()",
        RANDOM,
    ),
    ("crypto.randomUUID()", "crypto.randomUUID()", RANDOM),
    (
        "Crypto.prototype.randomUUID.call(crypto)",
        "crypto.randomUUID()",
        RANDOM,
    ),
    (
        "crypto.subtle.generateKey({name: 'AES-GCM', length: 128}, true, ['encrypt'])",
        "crypto.subtle.generateKey()",
        RANDOM,
    ),
    (
        "URL.createObjectURL(new Blob(['x']))",
        "URL.createObjectURL()",
        RANDOM,
    ),
    // Facts of this process or machine.
    ("Deno.memoryUsage()", "Deno.memoryUsage()", MACHINE),
    ("process.memoryUsage()", "process.memoryUsage()", MACHINE),
    ("process.cpuUsage()", "process.cpuUsage()", MACHINE),
    (
        "process.threadCpuUsage()",
        "process.threadCpuUsage()",
        MACHINE,
    ),
    ("process.umask()", "process.umask()", MACHINE),
    (
        "navigator.hardwareConcurrency",
        "navigator.hardwareConcurrency",
        MACHINE,
    ),
    // State kept on this machine between runs.
    ("localStorage", "`localStorage`", STATE),
    ("sessionStorage.length", "`sessionStorage`", STATE),
    ("caches", "`caches`", STATE),
    // Another set of globals.
    (
        "new Worker('data:application/javascript,0', {type: 'module'})",
        "`Worker`",
        REALM,
    ),
];

/// The rows of [`CLOSED_SOURCES`] `fgro` refuses before the driver's tables can, or
/// doesn't have at all, and what each says there: its own clock refusal for
/// `performance`, its refusal of code generation from strings, and a `ReferenceError`
/// for a global it lacks. The driver keeps the entries for the Deno form of the
/// wrapper (`builder.js`), whose tables it shares.
const FGRO_SAYS: &[(&str, &str)] = &[
    ("(0, eval)('Date.now()')", CODE_GENERATION),
    ("new Function('return new Date()')()", CODE_GENERATION),
    (
        "performance.now()",
        "performance.now() is refused in eval (clock): it reads the clock, so the value would differ from run to run; write the date or time as a literal with its offset, such as new Date('2026-01-01T00:00:00Z')",
    ),
    (
        "Object.getPrototypeOf(performance).now.call(performance)",
        "performance.now() is refused in eval (clock): it reads the clock, so the value would differ from run to run; write the date or time as a literal with its offset, such as new Date('2026-01-01T00:00:00Z')",
    ),
    (
        "performance.mark('m')",
        "performance.mark() is refused in eval (clock): it reads the clock, so the value would differ from run to run; write the date or time as a literal with its offset, such as new Date('2026-01-01T00:00:00Z')",
    ),
    (
        "performance.measure('m')",
        "performance.measure() is refused in eval (clock): it reads the clock, so the value would differ from run to run; write the date or time as a literal with its offset, such as new Date('2026-01-01T00:00:00Z')",
    ),
    (
        "performance.toJSON()",
        "performance.toJSON() is refused in eval (clock): it reads the clock, so the value would differ from run to run; write the date or time as a literal with its offset, such as new Date('2026-01-01T00:00:00Z')",
    ),
    (
        "performance.timeOrigin",
        "performance.timeOrigin is refused in eval (clock): it reads the clock, so the value would differ from run to run; write the date or time as a literal with its offset, such as new Date('2026-01-01T00:00:00Z')",
    ),
    ("new PerformanceMark('m')", "PerformanceMark is not defined"),
    ("new File([], 'f').lastModified", "File is not defined"),
    ("process.hrtime()", "process is not defined"),
    ("process.hrtime.bigint()", "process is not defined"),
    ("process.uptime()", "process is not defined"),
    (
        "crypto.getRandomValues(new Uint8Array(4))",
        "crypto is not defined",
    ),
    (
        "Object.getPrototypeOf(crypto).getRandomValues.call(crypto, new Uint8Array(4))",
        "crypto is not defined",
    ),
    ("crypto.randomUUID()", "crypto is not defined"),
    (
        "Crypto.prototype.randomUUID.call(crypto)",
        "Crypto is not defined",
    ),
    (
        "crypto.subtle.generateKey({name: 'AES-GCM', length: 128}, true, ['encrypt'])",
        "crypto is not defined",
    ),
    (
        "URL.createObjectURL(new Blob(['x']))",
        "Blob is not defined",
    ),
    ("Deno.memoryUsage()", "Deno is not defined"),
    ("process.memoryUsage()", "process is not defined"),
    ("process.cpuUsage()", "process is not defined"),
    ("process.threadCpuUsage()", "process is not defined"),
    ("process.umask()", "process is not defined"),
    ("navigator.hardwareConcurrency", "navigator is not defined"),
    ("localStorage", "localStorage is not defined"),
    ("sessionStorage.length", "sessionStorage is not defined"),
    ("caches", "caches is not defined"),
    (
        "new Worker('data:application/javascript,0', {type: 'module'})",
        "Worker is not defined",
    ),
];

/// What V8 says of code generation from strings, which `fgro` turns off.
const CODE_GENERATION: &str = "Code generation from strings disallowed for this context";

/// Closed sources Deno has only behind an `unstable` flag, as each is shown, and `fgro`
/// not at all: the driver's entry for it is skipped, and stays for the Deno form of the
/// wrapper. The `zap` binary's `config_sandbox_cli` test shows a working directory's
/// `deno.json` listing the flag doesn't bring it back.
const CLOSED_BEHIND_A_FLAG: &[&str] = &["Deno.openKv()"];

const CLOCK: &str = "reads the clock, so the config would declare something else each time it \
    runs; write the date or time it needs as a literal with its offset \
    (`new Date('2026-01-01T00:00:00Z')`)";
const RANDOM: &str = "is random, so the config would declare something else each time it runs; \
    write the value as a literal, or derive it from text the config holds";
const MACHINE: &str = "is a fact of this process or machine, so the config would declare \
    something else in another run; a config declares the same thing wherever it is evaluated";
const STATE: &str = "keeps data on this machine between runs, which a config may neither read \
    nor write; a config declares the same thing every time it is evaluated";
const REALM: &str = "runs code with globals of its own, which zap doesn't guard; compute what \
    the config needs in the config module itself";

/// The text of the one inline `file` a config declared — how a test reads back what a
/// config computed.
fn declared_text(config: &zap_types::schema::ZapConfig) -> &str {
    use zap_types::schema::{FileContent, ResourceKind};
    match &config.resources[0].kind {
        ResourceKind::File(file) => match &file.content {
            FileContent::Inline { content } => content,
            other => panic!("expected inline content, got {other:?}"),
        },
        other => panic!("expected a file, got {other:?}"),
    }
}

/// Every ambient source the wrapper closes throws where a config reaches it, and the
/// error says which source it was and what to write instead — the clock, randomness,
/// facts of the process, state kept between runs, another set of globals. One evaluation runs them all: the
/// config catches each refusal and declares what it said.
#[tokio::test]
async fn every_closed_ambient_source_throws_naming_itself() {
    if !fgro_available() {
        eprintln!("skipping every_closed_ambient_source_throws_naming_itself: ZAP_FGRO not set");
        return;
    }
    let mut sources = String::new();
    for (expression, _, _) in CLOSED_SOURCES {
        sources.push_str("\t() => ");
        sources.push_str(expression);
        sources.push_str(",\n");
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        &format!(
            r"
const sources = [
{sources}];
const said = sources.map((source) => {{
    try {{
        const value = source();
        return `no error: ${{typeof value}}`;
    }} catch (error) {{
        return error.message;
    }}
}});
export default (zap) => {{
    zap.target({{local: true}});
    zap.file({{id: 'said', path: '/said', content: {{type: 'inline', content: JSON.stringify(said)}}}});
}};
"
        ),
    );
    let config = eval_config(&path, pinned())
        .await
        .expect("the config itself evaluates");
    let said: Vec<String> = serde_json::from_str(declared_text(&config)).unwrap();
    assert_eq!(said.len(), CLOSED_SOURCES.len());
    for ((expression, name, why), said) in CLOSED_SOURCES.iter().zip(&said) {
        let expected = FGRO_SAYS
            .iter()
            .find(|(fgro_expression, _)| fgro_expression == expression)
            .map_or_else(
                || format!("zap config eval: {name} {why}"),
                |(_, said)| (*said).to_owned(),
            );
        assert_eq!(said, &expected, "{expression}");
    }
}

/// Every entry of the wrapper's tables of closed sources is exercised by a row of
/// [`CLOSED_SOURCES`] or named in [`CLOSED_BEHIND_A_FLAG`], so an entry can't be added —
/// or lost — without the test of it.
#[test]
fn every_closed_source_has_a_row() {
    let wrapper = zap_core::config::DRIVER_JS;
    let tables = &wrapper[wrapper.find("const CLOSED_FUNCTIONS = [").unwrap()
        ..wrapper.find("// The owner a table entry names").unwrap()];
    // A row is an entry's when it leads with the entry's whole name: the name itself, or
    // the name and then what was wrong with the call (` with no date`).
    let tested = |name: &str| {
        CLOSED_BEHIND_A_FLAG.contains(&name)
            || CLOSED_SOURCES.iter().any(|(_, shown, _)| {
                shown
                    .strip_prefix(name)
                    .is_some_and(|rest| rest.is_empty() || rest.starts_with(' '))
            })
    };
    let mut entries = 0;
    for line in tables.lines().map(str::trim) {
        // An entry that names what it is shown as: `[() => Owner, 'prop', 'shown', 'why'],`.
        let quoted: Vec<&str> = line.split('\'').skip(1).step_by(2).collect();
        let shown = match (line.starts_with("[() =>"), quoted.as_slice()) {
            (true, [_, shown, _]) => (*shown).to_owned(),
            // A constructor: `['Worker', 'realm'],`.
            (false, [name, _]) if line.starts_with("['") => format!("`{name}`"),
            _ => {
                // Every line of a table is an entry, a comment, or a bracket.
                assert!(
                    line.is_empty()
                        || line.starts_with("//")
                        || line.starts_with("const ")
                        || line == "];",
                    "a line of the wrapper's tables this test doesn't read: {line}"
                );
                continue;
            }
        };
        entries += 1;
        assert!(tested(&shown), "no row for the wrapper's `{shown}`");
    }
    // The tables were read: a change to their layout that this parse no longer follows
    // would otherwise pass with nothing checked.
    assert!(
        entries >= 30,
        "read only {entries} entries of the wrapper's tables"
    );
    // A name excused from a row here is an entry of the tables: one that was removed
    // from them, or renamed, is no longer closed by anything.
    for name in CLOSED_BEHIND_A_FLAG {
        assert!(
            tables.contains(&format!("'{name}'")),
            "`{name}` is excused from a row and is in none of the wrapper's tables"
        );
    }
}

/// A config that reads a closed source without catching the error is no config: the
/// evaluation fails, with the refusal in what it prints.
#[tokio::test]
async fn an_ambient_read_fails_the_evaluation() {
    if !fgro_available() {
        eprintln!("skipping an_ambient_read_fails_the_evaluation: ZAP_FGRO not set");
        return;
    }
    for (read, said) in [
        ("Date.now()", "zap config eval: Date.now() reads the clock"),
        (
            "new Date().toISOString()",
            "zap config eval: `new Date()` reads the clock",
        ),
        ("Math.random()", "zap config eval: Math.random() is random"),
    ] {
        let dir = scratch::tempdir().unwrap();
        let path = write_config(
            dir.path(),
            &format!(
                "export default (zap) => {{\n    zap.target({{local: true}});\n    \
                 zap.script({{id: 's', check: 'false', run: `echo ${{{read}}}`}});\n}};\n"
            ),
        );
        let error = eval_config(&path, pinned()).await.unwrap_err();
        assert_eq!(error.exit_code(), 2, "{read}");
        let Error::ConfigEval { message, .. } = error else {
            panic!("expected ConfigEval for a config reading {read}: {error:?}");
        };
        assert!(message.contains(said), "{read}: {message}");
    }
}

/// What a module builds as it loads is not refused, so nothing a config merely imports
/// fails it: a `FinalizationRegistry` and a `WeakRef`, as a generated WebAssembly
/// binding builds at load. The two are inert stand-ins: a reference always holds
/// its target and a registry never calls back, so neither shows what was collected.
#[tokio::test]
async fn what_the_runtime_reads_for_itself_is_not_refused() {
    if !fgro_available() {
        eprintln!("skipping what_the_runtime_reads_for_itself_is_not_refused: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
// What a wasm-bindgen module does as it loads.
let cleaned = 0;
const registry = new FinalizationRegistry(() => cleaned++);
const target = {};
const token = {};
registry.register(target, 'held', token);
const ref = new WeakRef(target);
const thrown = (run) => {
    try {
        run();
        return 'nothing';
    } catch (error) {
        return error.constructor.name;
    }
};
const values = [
    ref.deref() === target,
    ref instanceof WeakRef && registry instanceof FinalizationRegistry,
    Object.prototype.toString.call(ref) + Object.prototype.toString.call(registry),
    new (Object.getPrototypeOf(ref).constructor)(target).deref() === target,
    registry.unregister(token),
    registry.unregister(token),
    registry.register({}, 'held') === undefined,
    cleaned,
    thrown(() => WeakRef(target)),
    thrown(() => new WeakRef(1)),
    thrown(() => new FinalizationRegistry()),
    thrown(() => registry.register(target, target)),
    // The stand-ins, not the engine's own: those print as native code.
    [WeakRef, FinalizationRegistry].some((made) => String(made).includes('[native code]')),
];
export default (zap) => {
    zap.target({local: true});
    zap.file({id: 'values', path: '/values', content: {type: 'inline', content: JSON.stringify(values)}});
};
",
    );
    let config = eval_config(&path, pinned())
        .await
        .expect("the config evaluates");
    assert_eq!(
        declared_text(&config),
        r#"[true,true,"[object WeakRef][object FinalizationRegistry]",true,true,false,true,0,"TypeError","TypeError","TypeError","TypeError",false]"#
    );
}

/// A config evaluates jitless, so WebAssembly is absent: one that uses it fails, and
/// the hint is zap's — `fgro`'s names its own `--jit` flag, which zap doesn't pass.
#[tokio::test]
async fn webassembly_is_absent_and_the_hint_names_no_fgro_flag() {
    if !fgro_available() {
        eprintln!(
            "skipping webassembly_is_absent_and_the_hint_names_no_fgro_flag: ZAP_FGRO not set"
        );
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        "export default (zap) => {\n    zap.target({local: true});\n    \
         new WebAssembly.Module(new Uint8Array([0, 97, 115, 109, 1, 0, 0, 0]));\n};\n",
    );
    let error = eval_config(&path, pinned()).await.unwrap_err();
    let Error::ConfigEval { kind, message, .. } = &error else {
        panic!("expected ConfigEval: {error:?}");
    };
    assert_eq!(*kind, fuz_eval::EvalErrorKind::ModuleThrew);
    assert!(message.contains("WebAssembly is not defined"), "{message}");
    let rendered = error.render();
    assert!(
        rendered.contains("\nzap evaluates a config jitless: WebAssembly is absent"),
        "{rendered}"
    );
    assert!(!rendered.contains("--jit"), "{rendered}");
}

/// A config that allocates past `fgro`'s memory cap outside the heap — a 2 GiB
/// `ArrayBuffer` — fails as `memory`, and the hint is zap's: the cap is `fgro`'s.
#[tokio::test]
async fn a_config_past_the_memory_cap_fails_with_zap_s_hint() {
    if !fgro_available() {
        eprintln!("skipping a_config_past_the_memory_cap_fails_with_zap_s_hint: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        "const buffer = new ArrayBuffer(2 ** 31);\n\
         export default (zap) => {\n    zap.target({local: true});\n    void buffer;\n};\n",
    );
    let error = eval_config(&path, pinned()).await.unwrap_err();
    let Error::ConfigEval { kind, .. } = &error else {
        panic!("expected ConfigEval: {error:?}");
    };
    assert_eq!(*kind, fuz_eval::EvalErrorKind::Memory);
    let rendered = error.render();
    assert!(
        rendered.contains(" (memory): ")
            && rendered.contains("\nfgro caps an eval's process memory"),
        "{rendered}"
    );
}

/// Nothing a config prints reaches stdout, which carries the envelope alone: every
/// `console` method goes to stderr, and a `console.time` pair — which would read the
/// clock — prints without one.
#[tokio::test]
async fn nothing_a_config_prints_corrupts_the_declaration() {
    if !fgro_available() {
        eprintln!("skipping nothing_a_config_prints_corrupts_the_declaration: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
console.log('log'); console.info('info'); console.debug('debug');
console.table([{a: 1}]); console.dir({b: 2}); console.dirxml('x');
console.count('c'); console.countReset('c');
console.time('t'); console.timeLog('t'); console.timeEnd('t');
console.group('g'); console.groupCollapsed('h'); console.groupEnd(); console.groupEnd();
console.clear(); console.warn('warn'); console.trace('trace'); console.assert(false, 'assert');
export default (zap) => {
    zap.target({local: true});
    zap.directory({id: 'd', path: '/srv/d'});
};
",
    );
    let config = eval_config(&path, pinned())
        .await
        .expect("a config that prints still declares");
    assert_eq!(config.resources.len(), 1);
}

/// What is a function of the config's own text evaluates, to what the language
/// defines: string and JSON work, `Math` but `random`, a `Date` built from an instant,
/// a text or its parts, a clone, formatting. A `Date` subclass, `instanceof`, and an
/// `Intl` constructor called without `new` work, and so does code that assigns over
/// what a replaced method or `constructor` is inherited from. The time zone is the one
/// `fuz_eval` pins: a local `Date` reads UTC, and what formats with no locale given
/// formats as `en-US`.
#[tokio::test]
async fn pure_code_evaluates() {
    if !fgro_available() {
        eprintln!("skipping pure_code_evaluates: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
class Stamp extends Date {}
// The pre-class way to extend a built-in, and an own method over an inherited one.
function Legacy() {}
Legacy.prototype = Object.create(Date.prototype);
Legacy.prototype.constructor = Legacy;
class List extends Array {}
const list = new List();
const math = Object.create(Math);
math.random = () => 'own';
const values = [
    'ab'.toUpperCase() + JSON.parse(JSON.stringify({a: [1]})).a[0],
    Math.max(1, Math.floor(2.5)),
    new Date(0).toISOString(),
    new Date('2026-01-01T00:00:00Z').getTime(),
    new Date('2026-01-01T09:00:00+09:00').toISOString(),
    new Date('2026-01-02').getUTCDate(),
    new Date(new Date(5)).getTime(),
    Date.UTC(2020, 0, 1),
    Date.parse('2020-01-01T00:00:00Z'),
    Date.parse('Wed, 01 Jan 2020 00:00:00 GMT'),
    new Date(0) instanceof Date,
    new Stamp(7).getTime(),
    new Stamp(7) instanceof Stamp && new Stamp(7) instanceof Date,
    new Date(0).constructor === Date && Date.name,
    Object.getPrototypeOf(Date) === Function.prototype,
    JSON.stringify({at: new Date(0)}),
    structuredClone({a: [1, new Date(0)]}).a[1].toISOString(),
    new Date(0).toLocaleString('en-US', {timeZone: 'UTC'}),
    new Intl.DateTimeFormat('en-US', {timeZone: 'UTC', dateStyle: 'short'}).format(new Date(0)),
    Intl.NumberFormat('en-US').format(1234.5),
    new Intl.NumberFormat('en-US') instanceof Intl.NumberFormat,
    Intl.NumberFormat.supportedLocalesOf(['en-US']).join(),
    (1234.5).toLocaleString('de-DE'),
    ['b', 'a'].sort((x, y) => x.localeCompare(y, 'en')).join(''),
    'i'.toLocaleUpperCase('en'),
    Temporal.Instant.from('2020-01-01T00:00:00Z').epochMilliseconds,
    [3, 1, 2].sort().join(''),
    new Date('2026-01-01T09:00:30.5+0900').toISOString(),
    // A date alone and a date-time with an offset; an instant; a `Date`, read as its
    // instant; text in an object.
    new Date('2026-01-01').getTime(),
    new Date('+002026-01-01').getTime(),
    new Date(1767225600000).getTime(),
    new Date(new Date(0)).getTime() + new Date(new Stamp(3)).getTime(),
    new Date(new String('2026-01-01T00:00:00Z')).getTime(),
    new Date({valueOf: () => 9}).getTime(),
    new Date(new Date(0).toUTCString()).getTime() + new Date(new Date(0).toISOString()).getTime(),
    // The pinned zone and locale: what reads them reads UTC and `en-US`.
    new Date(2026, 0, 1).getTime(),
    new Date('2026-01-01T00:00').getTime(),
    new Date(0).getTimezoneOffset() + new Date(0).getHours(),
    new Intl.DateTimeFormat().resolvedOptions().timeZone,
    new Intl.NumberFormat().resolvedOptions().locale,
    (1234.5).toLocaleString(),
    'a'.localeCompare('b'),
    Legacy.prototype.constructor === Legacy && list instanceof List && math.random(),
];
export default (zap) => {
    zap.target({local: true});
    zap.file({id: 'values', path: '/values', content: {type: 'inline', content: JSON.stringify(values)}});
    zap.script({id: 's', check: 'false', run: `echo ${zap.env('ZAP_T_PURE')} ${values[1]}`});
};
",
    );
    let config = eval_config(&path, pinned())
        .await
        .expect("pure code evaluates");
    assert_eq!(
        declared_text(&config),
        r#"["AB1",2,"1970-01-01T00:00:00.000Z",1767225600000,"2026-01-01T00:00:00.000Z",2,5,1577836800000,1577836800000,1577836800000,true,7,true,"Date",true,"{\"at\":\"1970-01-01T00:00:00.000Z\"}","1970-01-01T00:00:00.000Z","1/1/1970, 12:00:00 AM","1/1/70","1,234.5",true,"en-US","1.234,5","ab","I",1577836800000,"123","2026-01-01T00:00:30.500Z",1767225600000,1767225600000,1767225600000,3,1767225600000,9,0,1767225600000,1767225600000,0,"UTC","en-US","1,234.5",-1,"own"]"#
    );
    let zap_types::schema::ResourceKind::Script(script) = &config.resources[1].kind else {
        panic!("expected a script");
    };
    assert_eq!(
        script.run.as_inert(),
        format!("echo {} 2", zap_types::var_ref::marker("ZAP_T_PURE"))
    );
}

/// A config that throws is reported in `fgro`'s words, uncoloured, and what the config
/// put in its message — an escape sequence, a carriage return, a line of its own —
/// prints escaped, under the `error:` it belongs to.
#[tokio::test]
async fn a_throwing_configs_error_renders_without_colour_and_escaped() {
    if !fgro_available() {
        eprintln!("skipping a_throwing_configs_error_renders: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r#"
export default (zap) => {
    zap.target({local: true});
    throw new Error("boom\r\x1b[2K\nplan_hash: 0000");
};
"#,
    );
    let error = eval_config(&path, pinned()).await.unwrap_err();
    let Error::ConfigEval { message, .. } = &error else {
        panic!("expected ConfigEval for a config that throws: {error:?}");
    };
    assert!(
        !message.contains("\u{1b}[0m") && !message.contains("\u{1b}[31m"),
        "{message:?}"
    );
    let rendered = error.render();
    assert!(!rendered.contains(['\r', '\u{1b}']), "{rendered:?}");
    let lines: Vec<&str> = rendered.lines().collect();
    assert!(
        lines[0].starts_with("error: config evaluation failed for ")
            && lines[0]
                .ends_with(" (module_threw): Uncaught (in promise) Error: boom<U+000D><U+001B>[2K"),
        "{rendered}"
    );
    assert_eq!(lines[1], "       plan_hash: 0000", "{rendered}");
    assert!(
        lines.iter().skip(1).all(|line| line.starts_with("       ")),
        "{rendered}"
    );
}

#[tokio::test]
async fn rejects_missing_default_export() {
    if !fgro_available() {
        eprintln!("skipping rejects_missing_default_export: ZAP_FGRO not set");
        return;
    }
    let failure = eval_failure("export const x = 1;\n").await;
    assert!(
        failure.contains(
            "zap config must export a default function: `export default (zap) => { ... }`"
        ),
        "{failure}"
    );
}

#[tokio::test]
async fn missing_config_is_a_clear_error() {
    if !fgro_available() {
        eprintln!("skipping missing_config_is_a_clear_error: ZAP_FGRO not set");
        return;
    }
    // Canonicalize fails before anything is pinned or spawned.
    let result = eval_config(Path::new("/definitely/not/here/zap.ts"), pinned()).await;
    assert!(matches!(result, Err(Error::ConfigNotFound { .. })));
}

#[tokio::test]
async fn allows_new_date_with_an_explicit_argument() {
    if !fgro_available() {
        eprintln!("skipping allows_new_date_with_an_explicit_argument: ZAP_FGRO not set");
        return;
    }
    // `new Date(0)` is deterministic (fixed input) and must stay allowed — only
    // the zero-arg clock read is rejected.
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    zap.target({local: true, package_manager: 'apt'});
    zap.script({id: 's', name: 's', check: 'false', run: `epoch ${new Date(0).toISOString()}`});
};
",
    );
    eval_config(&path, pinned())
        .await
        .expect("new Date(<arg>) should be allowed");
}

#[tokio::test]
async fn console_log_does_not_corrupt_output() {
    if !fgro_available() {
        eprintln!("skipping console_log_does_not_corrupt_output: ZAP_FGRO not set");
        return;
    }
    // A stray `console.log` in a config must land on stderr, not prepend text to
    // the JSON the parent parses from stdout.
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    console.log('debug: assembling config');
    zap.target({local: true, package_manager: 'apt'});
    zap.pkg({id: 'curl', name: 'curl', from: {apt: 'curl'}});
};
",
    );
    let config = eval_config(&path, pinned())
        .await
        .expect("a config that logs to stdout must still parse cleanly");
    assert_eq!(config.resources.len(), 1);
}

/// Overwrite the persisted L0 cache *value* with a sentinel config, leaving the
/// manifest valid (the source is untouched) — so whether a run served the cache or
/// re-eval'd is observable in the resource id it returns.
fn tamper_cached_value(zap_home: &Path, config_path: &Path) {
    let dir = eval_cache_dir_for(zap_home, config_path);
    let value: &[u8] = br#"{"target":{"local":true},"resources":[{"id":"FROM_CACHE","type":"directory","path":"/tmp/x"}]}"#;
    std::fs::write(dir.join("value.json"), value).unwrap();
    // The manifest names the value it vouches for: name the rewritten one, so a hit
    // serves it.
    let manifest = dir.join("manifest.json");
    let mut json: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&manifest).unwrap()).unwrap();
    json["value_blake3"] = blake3::hash(value).to_hex().to_string().into();
    std::fs::write(&manifest, serde_json::to_vec(&json).unwrap()).unwrap();
}

#[tokio::test]
async fn skip_mode_serves_the_cached_config_without_re_evaling() {
    if !fgro_available() {
        eprintln!(
            "skipping skip_mode_serves_the_cached_config_without_re_evaling: ZAP_FGRO not set"
        );
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    zap.target({local: true});
    zap.directory({id: 'FROM_EVAL', path: '/tmp/x'});
};
",
    );

    // First run: a miss eval's fresh and persists the value + manifest.
    let first = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(first.resources[0].id.0, "FROM_EVAL");

    // Tamper the cached value but leave the source (hence the manifest) valid.
    tamper_cached_value(home.path(), &path);

    // Skip mode must serve the (tampered) cached value — proving it did NOT re-eval
    // (a fresh eval would return `FROM_EVAL`).
    let hit = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        hit.resources[0].id.0, "FROM_CACHE",
        "skip mode should serve the cached value, not re-eval"
    );
}

#[tokio::test]
async fn shadow_mode_re_evals_and_ignores_the_cached_value() {
    if !fgro_available() {
        eprintln!("skipping shadow_mode_re_evals_and_ignores_the_cached_value: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    zap.target({local: true});
    zap.directory({id: 'FROM_EVAL', path: '/tmp/x'});
};
",
    );

    // Warm the cache, then tamper its value (manifest stays valid).
    eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Shadow,
        false,
    )
    .await
    .unwrap();
    tamper_cached_value(home.path(), &path);

    // Shadow mode always evals fresh and returns that — never the cached value (it
    // would log a SHADOW MISMATCH here, since fresh `FROM_EVAL` != cached `FROM_CACHE`).
    let fresh = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Shadow,
        false,
    )
    .await
    .unwrap();
    assert_eq!(fresh.resources[0].id.0, "FROM_EVAL");
}

/// A symbolic link retargeted is outside the key: the manifest records each module at
/// the real path it resolved to, so a link inside the project pointed at another file
/// moves no recorded hash. `Skip` serves the value the old target produced; `Shadow`
/// evaluates fresh and flags the mismatch — the case that keeps `Skip` opt-in.
///
/// This asserts a known gap, not a property to keep: once `fgro`'s graph dump records
/// the links a resolution traversed and the manifest captures them, the stale serve
/// below fails by design. Then flip the test to assert that `Skip` misses.
#[tokio::test]
async fn shadow_flags_a_retargeted_link_that_skip_serves_stale() {
    if !fgro_available() {
        eprintln!(
            "skipping shadow_flags_a_retargeted_link_that_skip_serves_stale: ZAP_FGRO not set"
        );
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    std::fs::write(dir.path().join("alpha.ts"), "export const id = 'alpha';\n").unwrap();
    std::fs::write(dir.path().join("beta.ts"), "export const id = 'beta';\n").unwrap();
    let data = dir.path().join("data.ts");
    std::os::unix::fs::symlink("alpha.ts", &data).unwrap();
    let path = write_config(
        dir.path(),
        "import {id} from './data.ts';\nexport default (zap) => {\n    \
         zap.target({local: true});\n    zap.directory({id, path: '/tmp/x'});\n};\n",
    );
    let first = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(first.resources[0].id.0, "alpha");

    std::fs::remove_file(&data).unwrap();
    std::os::unix::fs::symlink("beta.ts", &data).unwrap();

    let served = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        served.resources[0].id.0, "alpha",
        "the retarget moves no recorded hash, so Skip serves the old value"
    );
    let fresh = eval_config_raw(&path, pinned()).await.unwrap();
    assert_eq!(fresh.config.resources[0].id.0, "beta");
    assert_eq!(
        observe_and_persist(Some(home.path()), &path, &fresh),
        EvalCacheObservation::ShadowMismatch,
        "Shadow flags the value the retargeted link no longer produces"
    );
}

/// A `Skip` hit is served only when the binary hashes to the lock's pin: a warm entry
/// the same binary wrote is no hit once the lock pins another build, so the fresh eval
/// runs and refuses the binary, rather than serving what an unpinned build computed.
#[tokio::test]
async fn skip_serves_nothing_when_the_lock_pins_another_build() {
    if !fgro_available() {
        eprintln!(
            "skipping skip_serves_nothing_when_the_lock_pins_another_build: ZAP_FGRO not set"
        );
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        "export default (zap) => {\n    zap.target({local: true});\n};\n",
    );
    eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    // warm: the same pin is a hit, which serves the cached value as it stands
    tamper_cached_value(home.path(), &path);
    let hit = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(hit.resources[0].id.0, "FROM_CACHE", "the same pin hits");
    let other = zap_types::scalar::ContentHash::new("c".repeat(64)).unwrap();
    let repinned = zap_core::config::eval::PinnedFgro {
        pin: &other,
        ..pinned()
    };
    let error = eval_cached(
        Some(home.path()),
        &path,
        repinned,
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap_err();
    assert!(matches!(error, Error::FgroPinMismatch { .. }), "{error:?}");
}

/// An imported data module is an input: editing it is a miss, never served stale.
#[tokio::test]
async fn an_imported_data_module_is_captured() {
    if !fgro_available() {
        eprintln!("skipping an_imported_data_module_is_captured: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let data = dir.path().join("version.ts");
    std::fs::write(&data, "export const version = 'alpha';\n").unwrap();
    let path = write_config(
        dir.path(),
        "import {version} from './version.ts';\nexport default (zap) => {\n    \
         zap.target({local: true});\n    zap.directory({id: version, path: '/tmp/x'});\n};\n",
    );
    let first = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(first.resources[0].id.0, "alpha");
    std::fs::write(&data, "export const version = 'beta';\n").unwrap();
    let second = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(second.resources[0].id.0, "beta");
}

/// A config reached through a symlink is evaluated at its canonical path, so its
/// relative imports are the files beside the link's target; the manifest is captured
/// from that same path, so an edit to one of those files is a miss. Captured from the
/// path as given, the graph would hold the decoy beside the link instead, and the edit
/// would be served stale as a hit.
#[tokio::test]
async fn a_symlinked_config_s_manifest_holds_the_files_that_ran() {
    if !fgro_available() {
        eprintln!(
            "skipping a_symlinked_config_s_manifest_holds_the_files_that_ran: ZAP_FGRO not set"
        );
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let real = dir.path().join("real");
    let linked = dir.path().join("linked");
    std::fs::create_dir_all(&real).unwrap();
    std::fs::create_dir_all(&linked).unwrap();
    // The config's directory, pinned: one every user can write is refused.
    std::fs::set_permissions(&real, std::fs::Permissions::from_mode(0o755)).unwrap();
    let dep = |id: &str| format!("export const id = '{id}';\n");
    std::fs::write(real.join("dep.ts"), dep("one")).unwrap();
    std::fs::write(linked.join("dep.ts"), dep("decoy")).unwrap();
    scratch::write_config(
        real.join("zap.ts"),
        r"
import * as dep from './dep.ts';
export default (zap) => {
    zap.target({local: true});
    zap.directory({id: dep.id, path: '/tmp/x'});
};
",
    )
    .unwrap();
    let path = linked.join("zap.ts");
    std::os::unix::fs::symlink(real.join("zap.ts"), &path).unwrap();

    let id = |config: zap_types::schema::ZapConfig| config.resources[0].id.0.clone();
    let first = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(id(first), "one");
    std::fs::write(real.join("dep.ts"), dep("two")).unwrap();
    let second = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(
        id(second),
        "two",
        "an edit to a file the evaluation imported must miss, not be served stale"
    );
}

#[tokio::test]
async fn bust_forces_a_fresh_eval_over_a_skip_hit() {
    if !fgro_available() {
        eprintln!("skipping bust_forces_a_fresh_eval_over_a_skip_hit: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    zap.target({local: true});
    zap.directory({id: 'FROM_EVAL', path: '/tmp/x'});
};
",
    );

    // Warm the cache, then tamper its value (manifest stays valid) — a plain Skip run
    // would now serve the tampered value.
    eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    tamper_cached_value(home.path(), &path);

    // `--no-cache` (bust = true) must win over the Skip posture:
    // it ignores the cached value and re-evals fresh, returning `FROM_EVAL`.
    let busted = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        true,
    )
    .await
    .unwrap();
    assert_eq!(
        busted.resources[0].id.0, "FROM_EVAL",
        "a bust must force a fresh eval, not serve the cached value"
    );

    // The bust also re-persisted the fresh value, so the cache is warm again: a
    // subsequent ordinary Skip run hits the (now-correct) cache.
    let rewarmed = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(rewarmed.resources[0].id.0, "FROM_EVAL");
}

/// A config with no lock-eligible resources, so the lock verbs stay network-free.
const TARGET_FREE_CONFIG: &str = r"
export default (zap) => {
    zap.target({local: true});
    zap.directory({id: 'd', path: '/tmp/zap-test-dir'});
};
";

/// Assert a command left an L0 manifest behind — the observable proof it eval'd through
/// the cache rather than running `fgro` on its own.
fn assert_warmed_l0(label: &str, zap_home: &Path, config_path: &Path) {
    let manifest = eval_cache_dir_for(zap_home, config_path).join("manifest.json");
    assert!(manifest.is_file(), "{label} did not warm the L0 cache");
}

/// Every command core that evals a config goes through the L0 cache — including the
/// target-free ones (`status`, the lock verbs, `config validate`), which are the ones
/// that could quietly opt out by calling `eval_config` directly.
///
/// The stake isn't the saved eval: an eval outside `eval_cached` is also outside
/// the shadow-mismatch detector, and that detector running on *every* eval is what
/// justifies `Shadow` as the default posture.
#[tokio::test]
async fn the_target_free_commands_eval_through_the_l0_cache() {
    if !fgro_available() {
        eprintln!("skipping the_target_free_commands_eval_through_the_l0_cache: ZAP_FGRO not set");
        return;
    }
    // A fresh config dir + `~/.zap` per command, so each assertion is about that
    // command's own eval and not a sibling's leftovers.
    let fresh = || {
        let dir = scratch::tempdir().unwrap();
        let home = scratch::tempdir().unwrap();
        let path = write_config(dir.path(), TARGET_FREE_CONFIG);
        (dir, home, path)
    };

    let (_dir, home, path) = fresh();
    zap_core::commands::status::run_status_in(Some(home.path()), fgro(), &path)
        .await
        .unwrap();
    assert_warmed_l0("status", home.path(), &path);

    let (_dir, home, path) = fresh();
    zap_core::commands::lock::run_lock_in(Some(home.path()), fgro(), &path)
        .await
        .unwrap();
    assert_warmed_l0("lock", home.path(), &path);

    let (_dir, home, path) = fresh();
    zap_core::commands::lock::run_lock_check_in(Some(home.path()), fgro(), &path)
        .await
        .unwrap();
    assert_warmed_l0("lock --check", home.path(), &path);

    let (_dir, home, path) = fresh();
    zap_core::commands::update::run_update_in(Some(home.path()), fgro(), &path, &[])
        .await
        .unwrap();
    assert_warmed_l0("update", home.path(), &path);

    let (_dir, home, path) = fresh();
    zap_core::commands::run_config_validate_in(Some(home.path()), fgro(), &path)
        .await
        .unwrap();
    assert_warmed_l0("config validate", home.path(), &path);
}

/// Every command core over the config at `path`, each with a fresh `~/.zap`, labelled.
/// Only its error is kept: the gate tests ask how each one refuses.
async fn every_command_core(path: &Path) -> Vec<(&'static str, Result<(), Error>)> {
    use zap_core::commands::{
        ApplyOptions, DeployOptions, apply::run_apply_in, deploy::run_deploy_in,
        detect::run_detect_in, lock, plan::run_plan_in, run_config_validate_in,
        status::run_status_in, update::run_update_in,
    };
    let home = || scratch::tempdir().unwrap();
    let mut results = Vec::new();
    let h = home();
    let h = Some(h.path());
    results.push(("status", run_status_in(h, fgro(), path).await.map(drop)));
    let h = home();
    let h = Some(h.path());
    results.push(("lock", lock::run_lock_in(h, fgro(), path).await.map(drop)));
    let h = home();
    let h = Some(h.path());
    results.push((
        "lock --check",
        lock::run_lock_check_in(h, fgro(), path).await.map(drop),
    ));
    let h = home();
    let h = Some(h.path());
    results.push((
        "update",
        run_update_in(h, fgro(), path, &[]).await.map(drop),
    ));
    let h = home();
    let h = Some(h.path());
    results.push((
        "config validate",
        run_config_validate_in(h, fgro(), path).await.map(drop),
    ));
    let h = home();
    let h = Some(h.path());
    results.push((
        "detect",
        run_detect_in(h, fgro(), path, false, false).await.map(drop),
    ));
    let h = home();
    let h = Some(h.path());
    results.push((
        "plan",
        run_plan_in(h, fgro(), path, false, false).await.map(drop),
    ));
    let h = home();
    let h = Some(h.path());
    results.push((
        "apply",
        run_apply_in(h, fgro(), path, ApplyOptions::default())
            .await
            .map(drop),
    ));
    let h = home();
    let h = Some(h.path());
    results.push((
        "deploy",
        run_deploy_in(h, fgro(), path, &DeployOptions::default())
            .await
            .map(drop),
    ));
    results
}

/// Both config gates hold in every command core, the ones that bind a target and the
/// ones that bind none: a config the secret gate refuses, and one only the structure
/// gate refuses, each fail every command with that gate's error, before anything is
/// read from the machine.
#[tokio::test]
async fn every_command_core_runs_both_config_gates() {
    if !fgro_available() {
        eprintln!("skipping every_command_core_runs_both_config_gates: ZAP_FGRO not set");
        return;
    }
    // A fetch credential is a secret whatever `unmask` says: the secret gate refuses it.
    // The content is pinned, so no command would fetch it.
    let secret = r"
export default (zap) => {
    zap.target({local: true});
    zap.unmask('GH_PAT');
    zap.file({id: 'f', path: '/tmp/zap-gate-test-file', content: {type: 'remote',
        url: 'https://example.com/f', blake3: '0'.repeat(64),
        auth: {scheme: 'bearer', token: zap.env('GH_PAT')}}});
};
";
    // A relative working directory: the builder takes it, the structure gate refuses it.
    let structure = r"
export default (zap) => {
    zap.target({local: true});
    zap.script({id: 's', check: 'false', run: 'true', cwd: 'srv/app'});
};
";
    for (body, gate) in [(secret, "secret"), (structure, "structure")] {
        let dir = scratch::tempdir().unwrap();
        let path = write_config(dir.path(), body);
        for (label, result) in every_command_core(&path).await {
            match (gate, &result) {
                ("secret", Err(Error::Secret(message))) => {
                    assert!(
                        message.contains("zap.unmask('GH_PAT')"),
                        "{label}: {message}"
                    );
                }
                ("structure", Err(Error::Config(message))) => {
                    assert!(
                        message.contains("resource `s`: `cwd` is not an absolute path"),
                        "{label}: {message}"
                    );
                }
                _ => panic!("{label} passed a config the {gate} gate refuses: {result:?}"),
            }
        }
    }
}

/// The wire JSON a config evaluates to, as a value, and the config it parses to. The
/// config is in a project that links this checkout as `@fuzdev/zap`.
async fn wire_of(body: &str) -> serde_json::Value {
    let dir = scratch::tempdir().unwrap();
    zap_project(dir.path());
    let path = write_config(dir.path(), body);
    let zap_core::config::EvaluatedConfig {
        config,
        value_json: json,
        ..
    } = eval_config_raw(&path, pinned())
        .await
        .expect("eval should succeed");
    let wire: serde_json::Value = serde_json::from_str(&json).unwrap();
    // No marker leaves the evaluation: every reference is typed.
    assert!(!zap_types::var_ref::holds_delimiter(&json), "{json:?}");
    // And the engine's own serialization of what it parsed is the same wire value,
    // wherever the config declared one.
    let reserialized = serde_json::to_value(&config).unwrap();
    assert_eq!(reserialized["target"]["host"], wire["target"]["host"]);
    wire
}

/// The message a config's evaluation fails with.
async fn eval_failure(body: &str) -> String {
    let dir = scratch::tempdir().unwrap();
    let path = write_config(dir.path(), body);
    match eval_config(&path, pinned()).await {
        Err(Error::ConfigEval {
            message, stderr, ..
        }) => format!("{message}\n{stderr}"),
        other => panic!("expected the evaluation to fail, got {other:?}"),
    }
}

/// `zap.env` is converted at the boundary to the typed wire form, wherever a string
/// sits: alone, among other text, in an array, an `env` map, a template variable.
// `{env:NAME}` is the notation a reference is shown in, written out here as text.
#[allow(clippy::literal_string_with_formatting_args)]
#[tokio::test]
async fn the_builder_converts_references_to_their_wire_form() {
    if !fgro_available() {
        eprintln!("skipping the builder conversion test: ZAP_FGRO not set");
        return;
    }
    let wire = wire_of(
        r"
export default (zap) => {
    const domain = zap.env('DEPLOY_DOMAIN');
    zap.target({host: zap.env('DEPLOY_HOST'), user: 'deploy', bootstrap_user: 'root' + zap.env('B')});
    zap.file({
        id: 'site',
        path: `/etc/nginx/sites-available/${domain}.conf`,
        content: {type: 'template', template: 'server {{domain}} $$NOT$$;',
                  vars: {domain, port: 8080, plain: 'text $$X$$ {env:Y}', nested: {deep: [1, 'two']}}},
    });
    zap.script({id: 's', check: 'true', run: [domain, domain].join(''),
                env: {A: zap.env('A') + zap.env('B'), B: `x${zap.env('B')}`, C: 'plain'}});
    zap.database({id: 'db', engine: 'postgresql', database_name: 'app', username: zap.env('USER'),
                  auth: {method: 'md5', hosts: ['127.0.0.1/32', `${zap.env('NET')}/24`]}});
    zap.deploy({artifacts: ['build/'], path: '/srv/app',
                health: {domain, path: '/health'}});
};
",
    )
    .await;
    let env = |name: &str| serde_json::json!({"$env": name});
    assert_eq!(wire["target"]["host"], env("DEPLOY_HOST"));
    assert_eq!(wire["target"]["user"], "deploy");
    assert_eq!(
        wire["target"]["bootstrap_user"],
        serde_json::json!({"$text": ["root", env("B")]})
    );
    let site = &wire["resources"][0];
    assert_eq!(
        site["path"],
        serde_json::json!({"$text": ["/etc/nginx/sites-available/", env("DEPLOY_DOMAIN"), ".conf"]})
    );
    assert_eq!(site["content"]["template"], "server {{domain}} $$NOT$$;");
    assert_eq!(
        site["content"]["vars"],
        serde_json::json!({"domain": env("DEPLOY_DOMAIN"), "port": 8080,
            "plain": "text $$X$$ {env:Y}", "nested": {"deep": [1, "two"]}})
    );
    let script = &wire["resources"][1];
    assert_eq!(
        script["run"],
        serde_json::json!({"$text": [env("DEPLOY_DOMAIN"), env("DEPLOY_DOMAIN")]})
    );
    assert_eq!(
        script["env"],
        serde_json::json!({"A": {"$text": [env("A"), env("B")]},
            "B": {"$text": ["x", env("B")]}, "C": "plain"})
    );
    assert_eq!(
        wire["resources"][2]["auth"]["hosts"],
        serde_json::json!(["127.0.0.1/32", {"$text": [env("NET"), "/24"]}])
    );
    assert_eq!(wire["deploy"]["health"]["domain"], env("DEPLOY_DOMAIN"));
}

/// A reference is opaque while a config is evaluated: one that was sliced, split,
/// case-changed or encoded is an error naming where it sits, never a reference to
/// another name; and a reference can't be a key, nor a config's own object look like
/// one.
#[tokio::test]
async fn the_builder_refuses_a_damaged_or_misplaced_marker() {
    if !fgro_available() {
        eprintln!("skipping the damaged-marker test: ZAP_FGRO not set");
        return;
    }
    let config = |resource: &str| {
        format!(
            "export default (zap) => {{\n    zap.target({{local: true}});\n    {resource}\n}};\n"
        )
    };
    let script = |run: &str| {
        config(&format!(
            "zap.script({{id: 'go', check: 'true', run: {run}}});"
        ))
    };
    for (case, body, expected) in [
        (
            "sliced",
            script("zap.env('DEPLOY_DOMAIN').slice(1)"),
            "resource `go`.run holds a damaged `zap.env` reference",
        ),
        (
            "cut short",
            script("zap.env('DEPLOY_DOMAIN').slice(0, -1)"),
            "resource `go`.run holds a damaged `zap.env` reference",
        ),
        (
            "lowercased",
            script("zap.env('DEPLOY_DOMAIN').toLowerCase()"),
            "resource `go`.run holds a damaged `zap.env` reference",
        ),
        (
            "uppercased",
            script("zap.env('deploy_domain').toUpperCase()"),
            "resource `go`.run holds a damaged `zap.env` reference",
        ),
        (
            "split and rejoined",
            script("zap.env('DEPLOY_DOMAIN').split('_').join('-')"),
            "resource `go`.run holds a damaged `zap.env` reference",
        ),
        (
            "in an array",
            config(
                "zap.user({id: 'u', username: 'app', ssh_keys: {keys: ['a', zap.env('K').slice(2)]}});",
            ),
            "resource `u`.ssh_keys.keys[1] holds a damaged `zap.env` reference",
        ),
        (
            "in a template variable",
            config(
                "zap.file({id: 'f', path: '/f', content: {type: 'template', template: 't', \
                 vars: {domain: zap.env('D').toLowerCase()}}});",
            ),
            "resource `f`.content.vars.domain holds a damaged `zap.env` reference",
        ),
        (
            "in the target",
            "export default (zap) => { zap.target({host: zap.env('H').slice(1)}); };".to_owned(),
            "target.host holds a damaged `zap.env` reference",
        ),
        (
            "in a key",
            config("zap.script({id: 'go', check: 'true', run: 'x', env: {[zap.env('K')]: 'v'}});"),
            "resource `go`.env has a `zap.env` reference in a key (`zap.env('K')`)",
        ),
        (
            "a config's own `$env` key",
            config(
                "zap.file({id: 'f', path: '/f', content: {type: 'template', template: 't', \
                 vars: {data: {$env: 'HOME'}}}});",
            ),
            "resource `f`.content.vars.data has the key `$env`, which is reserved",
        ),
        (
            "a config's own `$text` key",
            config("zap.script({id: 'go', check: 'true', run: {$text: ['a', 'b']}});"),
            "resource `go`.run has the key `$text`, which is reserved",
        ),
        (
            "a reference as the id",
            config("zap.script({id: zap.env('ID').slice(1), check: 'true', run: 'x'});"),
            "resource 1.id holds a damaged `zap.env` reference",
        ),
    ] {
        let stderr = eval_failure(&body).await;
        assert!(stderr.contains(expected), "{case}: {stderr}");
        assert!(
            !zap_types::var_ref::holds_delimiter(&stderr),
            "{case}: the message prints a delimiter: {stderr:?}"
        );
    }
}

/// `zap.env`, `zap.mask` and `zap.unmask` take a variable's name and say so when called
/// with anything else — a reference in place of a name included.
#[tokio::test]
async fn the_builder_validates_names_when_called() {
    if !fgro_available() {
        eprintln!("skipping the name-validation test: ZAP_FGRO not set");
        return;
    }
    for (call, expected) in [
        (
            "zap.env('bad-name')",
            "zap.env: `bad-name` is not an environment variable's name",
        ),
        (
            "zap.env('')",
            "zap.env: `` is not an environment variable's name",
        ),
        (
            "zap.env('1X')",
            "zap.env: `1X` is not an environment variable's name",
        ),
        (
            "zap.env('$$X$$')",
            "zap.env: `$$X$$` is not an environment variable's name",
        ),
        (
            "zap.env(5)",
            "zap.env: a number is not an environment variable's name",
        ),
        (
            "zap.env()",
            "zap.env: nothing is not an environment variable's name",
        ),
        (
            "zap.env(zap.env('X'))",
            "zap.env: `zap.env('X')` is not an environment variable's name (a letter or `_`, \
             then letters, digits, or `_`) — pass the variable's name, not a reference to it",
        ),
        (
            "zap.mask(zap.env('X'))",
            "zap.mask: `zap.env('X')` is not an environment variable's name (a letter or `_`, \
             then letters, digits, or `_`) — pass the variable's name, not a reference to it",
        ),
        (
            "zap.mask('OK', 'not ok')",
            "zap.mask: `not ok` is not an environment variable's name",
        ),
        (
            "zap.unmask(zap.env('X'))",
            "zap.unmask: `zap.env('X')` is not an environment variable's name",
        ),
    ] {
        let body = format!("export default (zap) => {{ zap.target({{local: true}}); {call}; }};");
        let stderr = eval_failure(&body).await;
        assert!(stderr.contains(expected), "{call}: {stderr}");
        assert!(
            !zap_types::var_ref::holds_delimiter(&stderr),
            "{call}: {stderr:?}"
        );
    }
}

/// A reference in a field that takes none fails the parse with a finding that names the
/// resource, the field, and why — the whole message a command prints.
#[tokio::test]
async fn a_reference_in_a_field_that_takes_none_fails_the_eval_by_name() {
    if !fgro_available() {
        eprintln!("skipping the misplaced-reference test: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    zap.target({host: 'h.example', home: `/home/${zap.env('DEPLOY_USER')}`});
    zap.file({id: 'motd', path: '/etc/motd',
              content: {type: 'inline', content: `hello ${zap.env('NAME')}\n`}});
    zap.verify({id: 'v', assertions: [{type: 'command', run: `echo ${zap.env('X')}`}]});
    zap.pkg({id: 'jq', from: {apt: 'jq'}, check: `command -v ${zap.env('TOOL')}`});
    zap.file({id: 'conf', path: '/etc/conf', content: {type: 'template', template: 't',
              vars: {upstream: {host: zap.env('UPSTREAM')}}}});
};
",
    );
    let error = eval_config(&path, pinned()).await.unwrap_err();
    let Error::ConfigParse { source, .. } = &error else {
        panic!("{error:?}");
    };
    let findings: Vec<String> = source.to_string().lines().map(str::to_owned).collect();
    assert_eq!(
        findings,
        [
            "5 references in fields that take none:",
            "  - resource `motd`: `content.content` takes no reference: the content is written \
             as declared; put the value in a template's `vars`, which resolve",
            "  - resource `v`: `assertions[0].run` takes no reference: the command runs as \
             written; use a `script`, whose `check` resolves",
            "  - resource `jq`: `check` takes no reference: only a path check — one that begins \
             `/`, `~`, or `$HOME` — resolves, and a command check runs as written; use a \
             `script`, whose `check` resolves",
            "  - resource `conf`: `content.vars.upstream.host` takes no reference: a reference \
             inside a non-string var is not supported; pass it as its own var",
            "  - `target.home` takes no reference: this field is used as written",
        ]
    );
    assert_eq!(error.exit_code(), 2);
}

/// What a config's evaluation emits is read strictly, end to end: a value written by
/// position where its field is an object, a name written as an object, a key beside
/// `extract: {type: 'none'}`, and a restricted grant with no command each fail the
/// parse with the field named, exit 2.
#[tokio::test]
async fn a_config_written_in_a_shape_the_schema_does_not_have_is_rejected() {
    if !fgro_available() {
        eprintln!("skipping the config-shape test: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    for (body, expected) in [
        (
            "zap.file({id: 'motd', path: '/etc/motd', content: ['inline', 'x']});",
            "resource `motd`: `content` is an array where an object goes; zap reads an \
             object by its keys, never by position",
        ),
        (
            "zap.firewall({id: 'fw', backend: {ufw: null}, allow: []});",
            "resource `fw`: `backend.ufw` is null; leave the field out, or write its value",
        ),
        (
            "zap.file({id: 'bin', path: '/opt/bin', content: {type: 'remote', \
             url: 'https://e.x/a', extract: {type: 'none', strip_components: 1}}});",
            "`strip_components` belongs to a tar archive (`type: 'tar.xz'` or `'tar.gz'`); \
             `type: 'none'` writes the fetched bytes as they are and takes no other key",
        ),
        (
            "zap.user({id: 'u', username: 'deploy', sudo: {mode: 'nopasswd', commands: []}});",
            "`sudo.commands` is empty: a grant limited to no command grants nothing, and zap \
             does not read an empty list as every command; for a grant of every command \
             write the mode alone (`sudo: 'nopasswd'`), or list the commands the grant covers",
        ),
    ] {
        let path = write_config(
            dir.path(),
            &format!(
                "export default (zap) => {{\n    zap.target({{local: true}});\n    {body}\n}};\n"
            ),
        );
        let error = eval_config(&path, pinned()).await.unwrap_err();
        let Error::ConfigParse { source, .. } = &error else {
            panic!("{body}: {error:?}");
        };
        assert_eq!(source.to_string(), expected, "{body}");
        assert_eq!(error.exit_code(), 2);
    }
    let path = write_config(
        dir.path(),
        "export default (zap) => { zap.target([true]); };\n",
    );
    let error = eval_config(&path, pinned()).await.unwrap_err();
    assert!(
        error.to_string().ends_with(
            "`target` is an array where an object goes; zap reads an object by its keys, \
             never by position"
        ),
        "{error}"
    );
}

/// A finding names a resource by its id and a field by its path — the config's own
/// text. Each is escaped where the message is composed, so an id or a variable's name
/// that holds a line break can't add a finding to the list.
#[tokio::test]
async fn a_misplaced_reference_finding_escapes_the_names_it_holds() {
    if !fgro_available() {
        eprintln!("skipping the escaped-finding test: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    zap.target({local: true});
    zap.service({id: 'a\n  - resource `forged`: `x` takes no reference: y\u001b[2K',
                 service: zap.env('SVC')});
    zap.file({id: 'conf', path: '/etc/conf', content: {type: 'template', template: 't',
              vars: {'k\n  - forged': {host: zap.env('UPSTREAM')}}}});
};
",
    );
    let error = eval_config(&path, pinned()).await.unwrap_err();
    let Error::ConfigParse { source, .. } = &error else {
        panic!("{error:?}");
    };
    let message = source.to_string();
    let lines: Vec<&str> = message.lines().collect();
    assert_eq!(lines.len(), 3, "{message}");
    assert_eq!(lines[0], "2 references in fields that take none:");
    assert!(
        lines[1].starts_with(
            "  - resource `a<U+000A>  - resource `forged`: `x` takes no reference: \
             y<U+001B>[2K`: `service` takes no reference: "
        ),
        "{message}"
    );
    assert!(
        lines[2].starts_with(
            "  - resource `conf`: `content.vars.k<U+000A>  - forged.host` takes no reference: "
        ),
        "{message}"
    );
}

/// `env_ref`, a recipe's way to a reference, returns the string `zap.env` does, so a
/// recipe's result converts as a config's own reference would.
#[tokio::test]
async fn env_ref_and_zap_env_return_the_same_string() {
    if !fgro_available() {
        eprintln!("skipping the env_ref parity test: ZAP_FGRO not set");
        return;
    }
    let wire = wire_of(
        r"
import {env_ref} from '@fuzdev/zap/env_ref.ts';
import {debian_certbot_standalone_issue} from '@fuzdev/zap/recipe_debian_certbot.ts';

export default (zap) => {
    for (const name of ['DEPLOY_DOMAIN', '_x', 'A1']) {
        const [recipe, builder] = [env_ref(name), zap.env(name)];
        if (recipe !== builder || recipe !== '\uFDD0aZ:' + name + '\uFDD1') {
            throw new Error('env_ref and zap.env disagree about ' + name);
        }
    }
    for (const name of ['', '1X', 'A-B', 'a b', zap.env('X')]) {
        for (const make of [env_ref, zap.env]) {
            let threw = false;
            try { make(name); } catch { threw = true; }
            if (!threw) throw new Error('a bad name was accepted');
        }
    }
    zap.target({local: true});
    zap.script({id: 'recipe', check: 'true', run: `echo ${env_ref('FROM_RECIPE')}`});
    zap.script({id: 'ssl', ...debian_certbot_standalone_issue()});
};
",
    )
    .await;
    assert_eq!(
        wire["resources"][0]["run"],
        serde_json::json!({"$text": ["echo ", {"$env": "FROM_RECIPE"}]})
    );
    assert_eq!(
        wire["resources"][1]["check"],
        serde_json::json!({"$text": [
            "sudo test -f '/etc/letsencrypt/live/", {"$env": "DEPLOY_DOMAIN"}, "/fullchain.pem'",
        ]})
    );
}

/// A config whose default export is `async` has declared everything once the promise
/// it returns settles: what follows an `await` is declared too, a thenable is waited
/// for, and a rejection is the evaluation's error.
#[tokio::test]
async fn an_async_default_export_is_awaited() {
    if !fgro_available() {
        eprintln!("skipping an_async_default_export_is_awaited: ZAP_FGRO not set");
        return;
    }
    for body in [
        r"
export default async (zap) => {
    zap.target({local: true});
    for (let i = 0; i < 5; i++) await null;
    zap.directory({id: 'after', path: '/srv/after'});
};
",
        r"
export default (zap) => {
    zap.target({local: true});
    return {then: (resolve) => Promise.resolve().then(() => {
        zap.directory({id: 'after', path: '/srv/after'});
        resolve();
    })};
};
",
    ] {
        let wire = wire_of(body).await;
        assert_eq!(wire["resources"][0]["id"], "after", "{body}");
    }
    let failure = eval_failure(
        r"
export default async (zap) => {
    zap.target({local: true});
    await 0;
    throw new Error('the config gave up');
};
",
    )
    .await;
    assert!(failure.contains("the config gave up"), "{failure}");
}

/// A builder call made after the declaration was read fails the evaluation, naming the
/// method — from work the config left running, from a promise it didn't wait for, and
/// when the config catches the error the call throws.
#[tokio::test]
async fn a_builder_call_after_the_declaration_was_read_fails_the_evaluation() {
    if !fgro_available() {
        eprintln!("skipping the late-builder-call test: ZAP_FGRO not set");
        return;
    }
    let late = |call: &str| {
        format!(
            "export default (zap) => {{\n    zap.target({{local: true}});\n    \
             (async () => {{ for (let i = 0; i < 5; i++) await null; {call} }})();\n}};\n"
        )
    };
    for (body, method) in [
        (
            late("zap.directory({id: 'late', path: '/srv/late'});"),
            "directory",
        ),
        (late("zap.pkg({id: 'late', from: {apt: 'x'}});"), "pkg"),
        (late("zap.target({local: true});"), "target"),
        (
            late("zap.deploy({artifacts: [], path: '/srv/app'});"),
            "deploy",
        ),
        (late("zap.env('HOME');"), "env"),
        (late("zap.mask('A');"), "mask"),
        (late("zap.unmask('A');"), "unmask"),
        // caught by the config: the evaluation fails all the same
        (
            late("try { zap.script({id: 'late', check: 'c', run: 'r'}); } catch {}"),
            "script",
        ),
        // a promise the default export didn't wait for
        (
            "const later = async (zap) => {\n    for (let i = 0; i < 5; i++) await null;\n    \
             zap.service({id: 'late', service: 'x'});\n};\n\
             export default (zap) => {\n    zap.target({local: true});\n    later(zap);\n};\n"
                .to_owned(),
            "service",
        ),
    ] {
        let failure = eval_failure(&body).await;
        assert!(
            failure.contains(&format!(
                "zap.{method} was called after the config's default export had returned, so \
                 what it declares would be lost; the config has a promise it didn't wait for"
            )),
            "{method}: {failure}"
        );
    }
}

/// `zap.target` and `zap.deploy` each declare one block: a second call is an error
/// naming the method, never the first call replaced.
#[tokio::test]
async fn a_second_target_or_deploy_call_is_refused() {
    if !fgro_available() {
        eprintln!("skipping a_second_target_or_deploy_call_is_refused: ZAP_FGRO not set");
        return;
    }
    for (body, method) in [
        (
            "export default (zap) => {\n    zap.target({host: 'a.example'});\n    \
             zap.target({host: 'b.example'});\n};\n",
            "target",
        ),
        (
            "export default (zap) => {\n    zap.target({host: 'a.example'});\n    \
             zap.deploy({artifacts: ['a'], path: '/srv/a'});\n    \
             zap.deploy({artifacts: ['b'], path: '/srv/b'});\n};\n",
            "deploy",
        ),
    ] {
        let failure = eval_failure(body).await;
        assert!(
            failure.contains(&format!(
                "zap.{method} was called twice; a config declares one {method}"
            )),
            "{method}: {failure}"
        );
    }
}

/// The builder has a method per resource kind and no other: a call to a kind zap
/// doesn't have fails the evaluation as the `TypeError` it is, naming the call, and
/// declares nothing.
#[tokio::test]
async fn a_kind_the_builder_lacks_is_not_a_function() {
    if !fgro_available() {
        eprintln!("skipping a_kind_the_builder_lacks_is_not_a_function: ZAP_FGRO not set");
        return;
    }
    for method in ["repo", "container", "wormhole"] {
        let failure = eval_failure(&format!(
            "export default (zap) => {{\n    zap.target({{local: true}});\n    \
             zap.{method}({{id: 'x'}});\n}};\n"
        ))
        .await;
        assert!(
            failure.contains(&format!("TypeError: zap.{method} is not a function")),
            "{method}: {failure}"
        );
    }
}

/// A name is masked or it is not: one passed to both `zap.mask` and `zap.unmask` is an
/// error naming it, in whichever order the calls come.
#[tokio::test]
async fn a_name_both_masked_and_unmasked_is_refused() {
    if !fgro_available() {
        eprintln!("skipping a_name_both_masked_and_unmasked_is_refused: ZAP_FGRO not set");
        return;
    }
    let config = |calls: &str| {
        format!("export default (zap) => {{\n    zap.target({{local: true}});\n    {calls}\n}};\n")
    };
    for (calls, expected) in [
        (
            "zap.mask('APP_DSN', 'OTHER'); zap.unmask('PUBLIC', 'APP_DSN');",
            "zap.unmask: `APP_DSN` was also passed to zap.mask",
        ),
        (
            "zap.unmask('APP_DSN'); zap.mask('APP_DSN');",
            "zap.mask: `APP_DSN` was also passed to zap.unmask",
        ),
    ] {
        let failure = eval_failure(&config(calls)).await;
        assert!(failure.contains(expected), "{calls}: {failure}");
    }
    let wire = wire_of(&config("zap.mask('A', 'A'); zap.unmask('B');")).await;
    assert_eq!(wire["mask_vars"], serde_json::json!(["A", "A"]));
    assert_eq!(wire["unmask_vars"], serde_json::json!(["B"]));
}

/// A declared value is data: one JSON can't spell is an error naming where it sits,
/// never a field dropped or written as `null`. An object member left `undefined` is an
/// option left out.
#[tokio::test]
async fn a_declared_value_json_cannot_spell_is_refused() {
    if !fgro_available() {
        eprintln!("skipping a_declared_value_json_cannot_spell_is_refused: ZAP_FGRO not set");
        return;
    }
    let config = |declaration: &str| {
        format!(
            "class Port {{ constructor() {{ this.port = 22; }} }}\n\
             export default (zap) => {{\n    zap.target({{local: true}});\n    {declaration}\n}};\n"
        )
    };
    let file = |field: &str| {
        config(&format!(
            "zap.file({{id: 'conf', path: '/etc/conf', \
             content: {{type: 'inline', content: 'x'}}, {field}}});"
        ))
    };
    for (body, expected) in [
        (
            file("mode: () => '600'"),
            "resource `conf`.mode is a function; a config declares values",
        ),
        (
            file("mode: Symbol('600')"),
            "resource `conf`.mode is a symbol;",
        ),
        (file("mode: 600n"), "resource `conf`.mode is a bigint;"),
        (
            file("triggers: ['a', undefined]"),
            "resource `conf`.triggers[1] is undefined; an array holds a value at every position",
        ),
        (
            file("triggers: new Set(['a'])"),
            "resource `conf`.triggers is a `Set`, not a plain object",
        ),
        (
            file("content: new Map([['type', 'inline']])"),
            "resource `conf`.content is a `Map`, not a plain object",
        ),
        (
            file("mode: new String('600')"),
            "resource `conf`.mode is a `String`, not a plain object",
        ),
        (
            file("validate: new Date('2026-01-01T00:00:00Z')"),
            "resource `conf`.validate is a `Date`, not a plain object",
        ),
        (
            // a value's own `toJSON` is a function member, so it never gets to speak
            file("mode: {toJSON: () => '600'}"),
            "resource `conf`.mode.toJSON is a function;",
        ),
        (
            config("zap.firewall({id: 'fw', backend: 'ufw', allow: [new Port()]});"),
            "resource `fw`.allow[0] is a `Port`, not a plain object",
        ),
        (
            config("zap.firewall({id: 'fw', backend: 'ufw', allow: [{port: NaN}]});"),
            "resource `fw`.allow[0].port is NaN, which is not a number a config can declare",
        ),
        (
            config("zap.deploy({artifacts: ['a'], path: '/srv/a', releases: Infinity});"),
            "deploy.releases is Infinity, which is not a number",
        ),
        (
            config(
                "zap.deploy({artifacts: ['a'], path: '/srv/a', health: \
                 {domain: 'a.example', path: '/', attempts: -Infinity}});",
            ),
            "deploy.health.attempts is -Infinity, which is not a number",
        ),
        (
            config("zap.script({check: 'c', run: () => 'r'});"),
            "resource 1.run is a function;",
        ),
        (
            "export default (zap) => {\n    zap.target(new Map([['local', true]]));\n};\n"
                .to_owned(),
            "target is a `Map`, not a plain object",
        ),
        (
            config(
                "const rule = {port: 22};\n    rule.self = rule;\n    \
                 zap.firewall({id: 'fw', backend: 'ufw', allow: [rule]});",
            ),
            "resource `fw`.allow[0].self holds itself: it is a value that one of its own \
             members leads back to",
        ),
        (
            config(
                "const keys = ['a'];\n    keys.push(keys);\n    \
                 zap.file({id: 'conf', path: '/etc/conf', \
                 content: {type: 'inline', content: 'x'}, triggers: keys});",
            ),
            "resource `conf`.triggers[1] holds itself:",
        ),
        (
            "export default (zap) => {\n    zap.target({local: true, port: 0 / 0});\n};\n"
                .to_owned(),
            "target.port is NaN,",
        ),
    ] {
        let failure = eval_failure(&body).await;
        assert!(
            failure.contains(expected),
            "{expected}\n  not in: {failure}"
        );
    }

    // What is data is written as it was declared: an `undefined` member is left out, an
    // object with no prototype is an object, and a template variable keeps its shape.
    let wire = wire_of(&config(
        "zap.directory({id: 'd', path: '/srv/d', mode: undefined, owner: undefined});\n    \
         const bare = Object.create(null);\n    bare.port = 8080;\n    \
         zap.file({id: 't', path: '/etc/t', content: {type: 'template', template: '{{v}}', \
         vars: {v: {list: [1, 'two', true, null, [], {}], bare}}}});\n    \
         const shared = {port: 53, proto: 'udp'};\n    \
         zap.firewall({id: 'fw', backend: 'ufw', allow: [shared, shared, {port: 22}]});",
    ))
    .await;
    assert_eq!(
        wire["resources"],
        serde_json::json!([
            {"id": "d", "path": "/srv/d", "type": "directory"},
            {"id": "t", "path": "/etc/t", "type": "file",
             "content": {"type": "template", "template": "{{v}}",
                         "vars": {"v": {"list": [1, "two", true, null, [], {}],
                                        "bare": {"port": 8080}}}}},
            // one object placed in two fields is declared twice
            {"id": "fw", "backend": "ufw", "type": "firewall",
             "allow": [{"port": 53, "proto": "udp"}, {"port": 53, "proto": "udp"},
                       {"port": 22}]},
        ])
    );
}

/// One array placed in two fields, or twice in one list, is declared twice: only a
/// value that leads back to itself is refused.
#[tokio::test]
async fn an_array_placed_twice_is_declared_twice() {
    if !fgro_available() {
        eprintln!("skipping an_array_placed_twice_is_declared_twice: ZAP_FGRO not set");
        return;
    }
    let wire = wire_of(
        "export default (zap) => {\n    zap.target({local: true});\n    \
         const groups = ['adm', 'sudo'];\n    \
         zap.user({id: 'a', username: 'alice', groups});\n    \
         zap.user({id: 'b', username: 'bob', groups});\n    \
         zap.file({id: 't', path: '/etc/t', content: {type: 'template', template: '{{v}}', \
         vars: {v: [groups, groups]}}});\n};\n",
    )
    .await;
    assert_eq!(
        wire["resources"][0]["groups"],
        serde_json::json!(["adm", "sudo"])
    );
    assert_eq!(
        wire["resources"][1]["groups"],
        serde_json::json!(["adm", "sudo"])
    );
    assert_eq!(
        wire["resources"][2]["content"]["vars"]["v"],
        serde_json::json!([["adm", "sudo"], ["adm", "sudo"]])
    );
}

/// A `null` a config declares is an error naming the field, never the field read as
/// left out; a template variable's value is the one place it is data.
#[tokio::test]
async fn a_declared_null_fails_the_parse_by_name() {
    if !fgro_available() {
        eprintln!("skipping a_declared_null_fails_the_parse_by_name: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let config = |body: &str| {
        format!("export default (zap) => {{\n    zap.target({{local: true}});\n    {body}\n}};\n")
    };
    for (body, expected) in [
        (
            "zap.user({id: 'u', username: 'deploy', sudo: null});",
            "resource `u`: `sudo` is null; leave the field out, or write its value",
        ),
        (
            "zap.user({id: 'u', username: 'deploy', groups: ['adm', null]});",
            "resource `u`: `groups[1]` is null; leave the item out, or write its value",
        ),
        (
            "zap.deploy(null);",
            "`deploy` is null; leave the field out, or write its value",
        ),
    ] {
        let path = write_config(dir.path(), &config(body));
        let error = eval_config(&path, pinned()).await.unwrap_err();
        let Error::ConfigParse { source, .. } = &error else {
            panic!("{body}: {error:?}");
        };
        assert_eq!(source.to_string(), expected, "{body}");
        assert_eq!(error.exit_code(), 2);
    }
    let wire = wire_of(&config(
        "zap.file({id: 't', path: '/t', content: {type: 'template', template: '{{a}}', \
         vars: {a: null}}});",
    ))
    .await;
    assert_eq!(
        wire["resources"][0]["content"]["vars"]["a"],
        serde_json::Value::Null
    );
}

/// A cached value the parse refuses — one holding a `null` — is a miss: the config is
/// evaluated afresh, and the stale value is no error.
#[tokio::test]
async fn a_cached_value_the_parse_refuses_is_a_miss() {
    if !fgro_available() {
        eprintln!("skipping a_cached_value_the_parse_refuses_is_a_miss: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let home = scratch::tempdir().unwrap();
    let path = write_config(
        dir.path(),
        r"
export default (zap) => {
    zap.target({local: true});
    zap.directory({id: 'FROM_EVAL', path: '/tmp/x'});
};
",
    );
    eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    std::fs::write(
        eval_cache_dir_for(home.path(), &path).join("value.json"),
        r#"{"target":{"local":true},"deploy":null,"resources":[{"id":"FROM_CACHE","type":"directory","path":"/tmp/x","mode":null}]}"#,
    )
    .unwrap();
    let fresh = eval_cached(
        Some(home.path()),
        &path,
        pinned(),
        EvalCacheMode::Skip,
        false,
    )
    .await
    .unwrap();
    assert_eq!(fresh.resources[0].id.0, "FROM_EVAL");
}

/// The config evaluated is the file at the path given, whatever characters the path
/// holds: a `%`, `#`, `?`, backslash or newline in a directory or file name is part of
/// the name, not URL syntax. Read as a URL, `zap%41.ts` would be `zapA.ts`, a `#` or
/// `?` would end the path, a backslash would be a `/`, and a newline would be dropped,
/// each importing the impostor beside it.
#[tokio::test]
async fn the_config_evaluated_is_the_file_named_whatever_its_path_holds() {
    if !fgro_available() {
        eprintln!("skipping the config path test: ZAP_FGRO not set");
        return;
    }
    let dir = scratch::tempdir().unwrap();
    let declare = |id: &str| {
        format!(
            "export default (zap) => {{ zap.target({{local: true}}); \
             zap.directory({{id: '{id}', path: '/x'}}); }};\n"
        )
    };
    for (real, impostor) in [
        ("zap%41.ts", "zapA.ts"),
        ("a#b/zap.ts", "a"),
        ("q?x.ts", "q"),
        ("c\\d.ts", "c/d.ts"),
        ("e\nf.ts", "ef.ts"),
    ] {
        let real_path = dir.path().join(real);
        std::fs::create_dir_all(real_path.parent().unwrap()).unwrap();
        // The config's directory, pinned: one every user can write is refused.
        std::fs::set_permissions(
            real_path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        scratch::write_config(&real_path, declare("real")).unwrap();
        let impostor_path = dir.path().join(impostor);
        std::fs::create_dir_all(impostor_path.parent().unwrap()).unwrap();
        std::fs::write(&impostor_path, declare("impostor")).unwrap();
        let config = eval_config(&real_path, pinned())
            .await
            .unwrap_or_else(|error| panic!("{real:?}: {error}"));
        let ids: Vec<&str> = config.resources.iter().map(|r| r.id.0.as_str()).collect();
        assert_eq!(ids, ["real"], "{real:?}");
    }
}
