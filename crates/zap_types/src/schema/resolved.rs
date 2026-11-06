//! The fields a kind resolves at runtime ([`ResourceKind::resolved_fields`]), keyed by
//! a closed [`ResolvedField`] so a consumer can't name a field that doesn't exist, and
//! taken out with [`ResolvedFields::take`], which fails loudly when the kind didn't
//! resolve the field asked for.
//!
//! [`ResourceKind::resolved_fields`]: super::ResourceKind::resolved_fields

use std::collections::BTreeMap;
use std::fmt;

/// A field [`ResourceKind::resolved_fields`](super::ResourceKind::resolved_fields)
/// resolves, named as its kind's payload names it ([`as_str`](Self::as_str)).
///
/// The variants are in the order of their names, so [`ResolvedFields`] iterates (and a
/// consumer meets a refusal) in that order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum ResolvedField {
    /// An `installer`'s `check` path.
    Check,
    /// A `database`'s `database_name`.
    DatabaseName,
    /// A `build`'s `output` path.
    Output,
    /// The `path` of a `directory`, `file`, or `link`.
    Path,
    /// A `link`'s `target`.
    Target,
    /// A `database`'s `username`.
    Username,
}

impl ResolvedField {
    /// The field's name in its kind's payload — the key `config_hash` overlays its
    /// resolved value under, and the name a refusal of the value gives.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Check => "check",
            Self::DatabaseName => "database_name",
            Self::Output => "output",
            Self::Path => "path",
            Self::Target => "target",
            Self::Username => "username",
        }
    }
}

impl fmt::Display for ResolvedField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A field asked of a [`ResolvedFields`] that its kind doesn't resolve: the seam and
/// its consumer disagree, an internal fault surfaced rather than read as `""`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("internal: resolved field `{0}` missing from the seam")]
pub struct MissingResolvedField(pub ResolvedField);

/// A kind's resolved fields: each [`ResolvedField`] it resolves, with its value.
///
/// Its `Debug` names each field and shows no value: a value is resolved, and may hold a
/// secret's.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ResolvedFields(BTreeMap<ResolvedField, String>);

impl fmt::Debug for ResolvedFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map()
            .entries(self.0.keys().map(|field| (field, crate::secrecy::Redacted)))
            .finish()
    }
}

impl ResolvedFields {
    /// The value of `field`, if its kind resolves it.
    #[must_use]
    pub fn get(&self, field: ResolvedField) -> Option<&str> {
        self.0.get(&field).map(String::as_str)
    }

    /// Take the value of `field` out.
    ///
    /// # Errors
    /// [`MissingResolvedField`] when the kind doesn't resolve `field` (or it was taken).
    pub fn take(&mut self, field: ResolvedField) -> Result<String, MissingResolvedField> {
        self.0.remove(&field).ok_or(MissingResolvedField(field))
    }

    /// Each field with its value, in [`ResolvedField`] order.
    pub fn iter(&self) -> impl Iterator<Item = (ResolvedField, &str)> {
        self.0.iter().map(|(field, value)| (*field, value.as_str()))
    }

    /// Replace each value by `f` of it, in [`ResolvedField`] order, stopping at the first
    /// error.
    ///
    /// # Errors
    /// The first error `f` returns.
    pub fn try_map<E>(
        self,
        mut f: impl FnMut(ResolvedField, String) -> Result<String, E>,
    ) -> Result<Self, E> {
        self.0
            .into_iter()
            .map(|(field, value)| f(field, value).map(|value| (field, value)))
            .collect()
    }
}

impl<const N: usize> From<[(ResolvedField, String); N]> for ResolvedFields {
    fn from(fields: [(ResolvedField, String); N]) -> Self {
        Self(fields.into())
    }
}

impl FromIterator<(ResolvedField, String)> for ResolvedFields {
    fn from_iter<I: IntoIterator<Item = (ResolvedField, String)>>(iter: I) -> Self {
        Self(iter.into_iter().collect())
    }
}

#[cfg(test)]
mod tests {
    use super::{MissingResolvedField, ResolvedField, ResolvedFields};

    /// The `Debug` of resolved fields names each field and shows no value.
    #[test]
    fn debug_names_the_fields_and_shows_no_value() {
        let fields =
            ResolvedFields::from([(ResolvedField::Path, "/srv/hunter2-s3cret".to_owned())]);
        let shown = format!("{fields:?} {fields:#?}");
        assert!(
            shown.contains("Path") && shown.contains("<redacted>"),
            "{shown}"
        );
        assert!(!shown.contains("hunter2"), "{shown}");
    }

    /// The variants' order is their names' order, so iterating keeps the order the
    /// string-keyed map had.
    #[test]
    fn fields_order_by_name() {
        let all = [
            ResolvedField::Check,
            ResolvedField::DatabaseName,
            ResolvedField::Output,
            ResolvedField::Path,
            ResolvedField::Target,
            ResolvedField::Username,
        ];
        assert!(all.is_sorted());
        assert!(all.map(ResolvedField::as_str).is_sorted());
    }

    #[test]
    fn a_field_the_kind_does_not_resolve_is_a_loud_miss() {
        let mut fields: ResolvedFields =
            std::iter::once((ResolvedField::Path, "/a".to_owned())).collect();
        assert_eq!(
            fields.take(ResolvedField::Target),
            Err(MissingResolvedField(ResolvedField::Target))
        );
        assert_eq!(fields.take(ResolvedField::Path).as_deref(), Ok("/a"));
        assert_eq!(
            MissingResolvedField(ResolvedField::Path).to_string(),
            "internal: resolved field `path` missing from the seam"
        );
    }
}
