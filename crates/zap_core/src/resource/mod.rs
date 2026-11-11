//! Resource detection and execution over a [`Connection`].
//!
//! Detection is the IO half of planning: it probes
//! the target and produces `Detection` outcomes that the pure plan-diff
//! (`zap_types::plan::diff`) consumes; execution applies the resulting plan fact.
//! Every resource kind detects and executes.
//!
//! [`Connection`]: crate::connection::Connection

pub mod detect;
pub mod execute;
pub mod pending;

pub use detect::{DetectionPass, Markers, detect_all, detect_resource};
pub use execute::{ChangeRecord, Executed, execute_plan, refused_changes};

use zap_types::schema::{ResolvedField, ResolvedFields, ResourceKind};
use zap_types::validate::resolved_field_problem;

use crate::connection::Connection;
use crate::error::{Error, Result};
use crate::resolve::UnsafeValue;

/// A pin's short display prefix (first 12 hex chars). `get` keeps it total — a pin is
/// ASCII hex, but byte-slicing a `&str` would panic on a non-char-boundary for any
/// other input.
pub(crate) fn short_pin(pin: &str) -> &str {
    pin.get(..12).unwrap_or(pin)
}

/// Resolve a kind's runtime fields for IO — the seam detection and execution share.
///
/// The pure [`ResourceKind::resolved_fields`] seam picks *which* fields (paths, plus
/// `database`'s identifiers); [`Connection::apply_home`] then resolves references and
/// finishes `~` / `$HOME` against the target (operator `$HOME` local, declared
/// `target.home` remote). Reusing it in both stages keeps the resolved value the
/// detector probes identical to the one the executor writes.
///
/// A resolved value is then held to what its field is — a path absolute and one line, a
/// `database`'s names ones a `pg_hba.conf` rule line reads as themselves — which the
/// structural gate could check only as far as the field was written out.
///
/// # Errors
/// The first field that doesn't resolve (an undeclared remote home referenced by a
/// path, a value holding a NUL or a delimiter), or whose value its field can't be
/// ([`UnsafeValue::Field`], naming the field and never the value).
pub(crate) fn resolve_kind_fields(
    conn: &Connection,
    kind: &ResourceKind,
) -> Result<ResolvedFields> {
    let resolved = kind
        .resolved_fields(str::to_owned)
        .try_map(|field, literal| {
            let resolved = conn.apply_home(&literal)?;
            UnsafeValue::held_to(field.as_str(), resolved, |value| {
                resolved_field_problem(field, value)
            })
            .map_err(Error::UnusableValue)
        })?;
    // A link whose target, absolute or from the link's directory, is zap's state, under
    // it, or a directory above it leads paths below it there; one placed at a directory
    // above it would replace that directory.
    if let ResourceKind::Link(_) = kind
        && let (Some(path), Some(target)) = (
            resolved.get(ResolvedField::Path),
            resolved.get(ResolvedField::Target),
        )
        && zap_types::claim::link_reaches_zap_state(path, target)
    {
        return Err(Error::UnusableValue(UnsafeValue::Field {
            field: ResolvedField::Target.as_str().to_owned(),
            problem: zap_types::claim::ZAP_STATE_LINK_PROBLEM,
        }));
    }
    if let ResourceKind::Link(_) = kind
        && let Some(path) = resolved.get(ResolvedField::Path)
        && zap_types::claim::link_replaces_zap_state_ancestor(path)
    {
        return Err(Error::UnusableValue(UnsafeValue::Field {
            field: ResolvedField::Path.as_str().to_owned(),
            problem: zap_types::claim::ZAP_STATE_ANCESTOR_LINK_PROBLEM,
        }));
    }
    Ok(resolved)
}

#[cfg(test)]
mod tests {
    use zap_types::schema::Resource;

    use super::resolve_kind_fields;
    use crate::connection::{Connection, MockConnection};
    use crate::error::Error;

    /// A path that resolves into zap's own state — through its home and a `..`, or a
    /// link's relative target — is refused where the value resolves, which detection and
    /// the wetrun share; one beside it resolves.
    #[test]
    fn a_resolved_path_into_zaps_state_is_refused() {
        let conn = Connection::Mock(MockConnection::new("m").with_home("/root"));
        let resolve = |json: serde_json::Value| {
            let resource: Resource = serde_json::from_value(json).unwrap();
            resolve_kind_fields(&conn, &resource.kind)
        };
        let refused = |result: crate::error::Result<_>, field: &str| match result {
            Err(Error::UnusableValue(error)) => assert!(
                error
                    .to_string()
                    .starts_with(&format!("`{field}` resolves to a value that "))
                    && error.to_string().contains("`/var/lib/zap`"),
                "{error}"
            ),
            other => panic!("{other:?}"),
        };
        refused(
            resolve(serde_json::json!({"id": "f", "type": "directory",
                "path": "~/../var/lib/zap/x"})),
            "path",
        );
        refused(
            resolve(serde_json::json!({"id": "l", "type": "link",
                "path": "~/state", "target": "../var/lib/zap"})),
            "target",
        );
        refused(
            resolve(serde_json::json!({"id": "l", "type": "link",
                "path": "~/../../var/lib", "target": "/srv"})),
            "path",
        );
        for above in ["/", "/var/lib", "../var"] {
            refused(
                resolve(serde_json::json!({"id": "l", "type": "link",
                    "path": "~/state", "target": above})),
                "target",
            );
        }
        assert!(
            resolve(serde_json::json!({"id": "l", "type": "link",
                "path": "~/state", "target": "../var/lib/zapper"}))
            .is_ok()
        );
    }
}
