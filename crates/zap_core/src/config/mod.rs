//! Config evaluation — runs `zap.ts` through a pinned `fgro eval` (gro's runtime, via
//! the shared `fuz_eval` crate) and parses the value into the `zap_types` schema.
//!
//! The operator-facing builder API, and the tables of ambient inputs a config is
//! refused, are [`DRIVER_JS`], an ES module (`builder_fgro.js`, embedded at compile
//! time) written to `fgro`'s stdin as its driver. The spawn and the parse live in
//! [`eval`]; which `fgro` runs, and the blake3 it must hash to, are [`fgro`]'s.

pub mod eval;
pub mod eval_cache;
pub mod fgro;

pub use eval::{EvaluatedConfig, eval_config, eval_config_raw};
pub use eval_cache::{EvalCacheMode, EvalCacheObservation, eval_cached, mode_from_env};

/// The embedded eval driver (the builder API and the refused ambient inputs), written
/// to `fgro eval`'s stdin.
///
/// Read from `builder_fgro.js` beside this module and embedded at compile time; its
/// blake3 is part of the eval cache's key ([`eval_cache`]) and is what `fgro`'s
/// envelope must name. It lives under `crates/`, outside the site's `src/`, so the
/// site's JS tooling doesn't format it, and `eslint.config.js` ignores it. Must stay in
/// sync with `zap_types::schema` — it returns the JSON that schema parses.
///
/// `builder.js` beside it is the Deno form of the same wrapper, which zap doesn't
/// run: gro's eval benchmark reads it for its Deno row, and the tests below keep the
/// two in step.
pub const DRIVER_JS: &str = include_str!("builder_fgro.js");

#[cfg(test)]
mod tests {
    use zap_types::schema::ResourceType;

    use super::DRIVER_JS as BUILDER_FGRO_JS;

    /// The Deno form of [`BUILDER_FGRO_JS`], which zap doesn't run: gro's eval
    /// benchmark reads `builder.js` for its Deno row, so these tests keep it in step
    /// with the driver.
    const BUILDER_JS: &str = include_str!("builder.js");

    /// Pull the wire values out of a wrapper's `RESOURCE_TYPES` map (the
    /// `'package'` in `pkg: 'package',`), so a test can compare them to the
    /// schema's `ResourceType`.
    fn wrapper_resource_kinds(wrapper: &str) -> Vec<String> {
        let start = wrapper
            .find("const RESOURCE_TYPES = {")
            .expect("wrapper declares RESOURCE_TYPES");
        let block = &wrapper[start..];
        let end = block.find("};").expect("RESOURCE_TYPES object is closed");
        let mut kinds = Vec::new();
        for line in block[..end].lines() {
            if let Some(idx) = line.find(": '") {
                let rest = &line[idx + 3..];
                if let Some(close) = rest.find('\'') {
                    kinds.push(rest[..close].to_owned());
                }
            }
        }
        kinds
    }

    /// Each wrapper's resource-kind set must equal `ResourceType` exactly. Adding
    /// a kind to one side without the other would drift silently until a real
    /// config hit it; nothing else couples the embedded JS to the schema.
    #[test]
    fn builder_js_kinds_match_resource_type() {
        let wrapper = wrapper_resource_kinds(BUILDER_FGRO_JS);

        // Every wrapper kind parses to a `ResourceType` (wrapper ⊆ enum).
        for kind in &wrapper {
            let parsed: Result<ResourceType, _> = serde_json::from_str(&format!("\"{kind}\""));
            assert!(
                parsed.is_ok(),
                "wrapper emits unknown resource kind {kind:?}"
            );
        }

        // Every `ResourceType` appears in the wrapper (enum ⊆ wrapper)…
        for variant in ResourceType::ALL {
            assert!(
                wrapper.iter().any(|k| k == variant.as_str()),
                "wrapper is missing resource kind {:?}",
                variant.as_str(),
            );
        }

        // …and the counts match, so neither side carries an extra kind.
        assert_eq!(
            wrapper.len(),
            ResourceType::ALL.len(),
            "wrapper kind count != ResourceType::ALL count",
        );
    }

    /// The fgro driver declares the same resource kinds as `builder.js`, so gro's
    /// eval benchmark row stays in step.
    #[test]
    fn builder_fgro_js_kinds_match_builder_js() {
        assert_eq!(
            wrapper_resource_kinds(BUILDER_FGRO_JS),
            wrapper_resource_kinds(BUILDER_JS),
        );
    }

    /// Outside the hunks the port changes (the header, the `Deno.noColor`
    /// guard, the stdout reroute, the seal's status, and sections 4 and 5),
    /// the driver is `builder.js` byte for byte.
    #[test]
    fn builder_fgro_js_shares_builder_js_code() {
        let span = |wrapper: &'static str, from: &str, to: &str| {
            let moved = |anchor: &str| -> ! {
                panic!(
                    "`{anchor}` not found: builder.js or builder_fgro.js moved a drift-test anchor; update the anchors in this test"
                )
            };
            let start = wrapper.find(from).unwrap_or_else(|| moved(from));
            let end = start + wrapper[start..].find(to).unwrap_or_else(|| moved(to));
            &wrapper[start..end]
        };
        for (from, to, fgro_to) in [
            (
                "// --- 1. Determinism",
                "// What a config's output is captured",
                None,
            ),
            (
                "// The garbage collector",
                "// --- 1b.",
                Some("// --- 2. References"),
            ),
            (
                "// --- 2. References",
                "// Set when the declaration is read",
                None,
            ),
            (
                "const open = (method) => {",
                "\tDeno.exitCode = 1;",
                Some("\tlate = true;"),
            ),
            ("const message =", "// --- 4. Evaluate", None),
        ] {
            assert!(
                span(BUILDER_FGRO_JS, from, fgro_to.unwrap_or(to)) == span(BUILDER_JS, from, to),
                "the span from `{from}` differs from builder.js"
            );
        }
    }

    /// Sections 4 and 5 run inside the driver's default export, so they are
    /// re-indented there: the code they share with `builder.js` (the default
    /// export's check and call, `named`, `wire_of`, and the emitted fields)
    /// matches line for line once each line is trimmed and blank lines are
    /// dropped, the config's namespace standing for `module` and `return`
    /// for the `config` binding.
    #[test]
    fn builder_fgro_js_evaluates_and_emits_as_builder_js() {
        let lines = |wrapper: &'static str, from: &str, last: &str| -> Vec<String> {
            let ported = |line: &str| {
                let line = line.trim().replace("namespace.default", "module.default");
                if line == "return {" {
                    "const config = {".to_owned()
                } else {
                    line
                }
            };
            let start = wrapper.find(from).unwrap_or_else(|| {
                panic!(
                    "`{from}` not found: builder.js or builder_fgro.js moved a drift-test anchor; update the anchors in this test"
                )
            });
            let mut kept = Vec::new();
            for line in wrapper[start..].lines().map(ported) {
                let done = line.starts_with(last);
                if !line.is_empty() {
                    kept.push(line);
                }
                if done {
                    return kept;
                }
            }
            panic!("no line starts with `{last}`");
        };
        for (from, fgro_from, last) in [
            (
                "if (typeof module.default",
                "if (typeof namespace.default",
                "await module.default(",
            ),
            ("sealed = true;", "sealed = true;", "unmask_vars:"),
        ] {
            assert_eq!(
                lines(BUILDER_FGRO_JS, fgro_from, last),
                lines(BUILDER_JS, from, last),
                "the lines from `{from}` differ from builder.js"
            );
        }
    }
}
