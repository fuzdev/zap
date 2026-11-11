//! The result table a wetrun prints under its header, `apply`'s and `deploy`'s alike:
//! one row per thing it ran, each with its status, what it is, how long it took, and
//! what it says, in aligned columns; and the form a measured duration takes there and
//! on the closing verdict line.

use std::fmt::Write as _;
use std::time::Duration;

use crate::escape::render_block;

/// One row of a wetrun's table.
pub(super) struct Row {
    /// `ok`, `FAIL`, or `skip`.
    pub(super) status: &'static str,
    /// What the row is (a change's resource id, a step id, `preflight`), escaped.
    pub(super) id: String,
    /// How long it ran ([`format_elapsed`]), or empty for one that didn't.
    pub(super) took: String,
    /// What opens its text column ahead of the text, escaped (`apply`'s
    /// `[ExecutionFailed]  — `); the text's further lines align under the text, past it.
    /// Empty for none.
    pub(super) tag: String,
    /// Its summary, error, or reason, escaped as a block when written; may be empty.
    pub(super) text: String,
}

/// `rows` as a table: the status, the id padded to the widest, the duration
/// right-aligned in its own column, then the tag and the text, the text's further lines
/// aligned under its first.
///
/// The id is the first field after the status, whatever follows it, and holds no
/// whitespace (a resource id can't, a step id doesn't): a reader of the table takes it as
/// the first whitespace-separated field of the row.
pub(super) fn render_rows(out: &mut String, rows: &[Row]) {
    let id_width = rows
        .iter()
        .map(|row| row.id.chars().count())
        .max()
        .unwrap_or(0);
    let took_width = rows
        .iter()
        .map(|row| row.took.chars().count())
        .max()
        .unwrap_or(0);
    for row in rows {
        // a table with no time in it has no column for one
        let lead = if took_width == 0 {
            format!("  {:<6}{:<id_width$}", row.status, row.id)
        } else {
            format!(
                "  {:<6}{:<id_width$}  {:>took_width$}",
                row.status, row.id, row.took
            )
        };
        if row.tag.is_empty() && row.text.is_empty() {
            let _ = writeln!(out, "{}", lead.trim_end());
        } else {
            render_block(out, &format!("{lead}  {}", row.tag), &row.text);
        }
    }
}

/// A duration as a row or a verdict line shows it, truncated: tenths of a second under
/// ten seconds (`0.4s`, and `9.9s` for 9999 ms), whole seconds under a minute (`42s`),
/// then minutes and seconds (`3m 07s`) and hours and minutes (`1h 02m`).
pub(super) fn format_elapsed(took: Duration) -> String {
    let tenths = took.as_millis() / 100;
    if tenths < 100 {
        return format!("{}.{}s", tenths / 10, tenths % 10);
    }
    let seconds = took.as_secs();
    if seconds < 60 {
        format!("{seconds}s")
    } else if seconds < 3600 {
        format!("{}m {:02}s", seconds / 60, seconds % 60)
    } else {
        format!("{}h {:02}m", seconds / 3600, seconds % 3600 / 60)
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use super::{Row, format_elapsed, render_rows};

    /// A duration reads in tenths of a second, then whole seconds, then minutes and hours.
    #[test]
    fn a_duration_reads_at_the_scale_it_is() {
        for (millis, shown) in [
            (0, "0.0s"),
            (49, "0.0s"),
            (420, "0.4s"),
            (9_999, "9.9s"),
            (10_000, "10s"),
            (59_999, "59s"),
            (60_000, "1m 00s"),
            (187_000, "3m 07s"),
            (3_600_000, "1h 00m"),
            (3_720_000, "1h 02m"),
        ] {
            assert_eq!(format_elapsed(Duration::from_millis(millis)), shown);
        }
    }

    fn row(status: &'static str, id: &str, took: &str, tag: &str, text: &str) -> Row {
        Row {
            status,
            id: id.to_owned(),
            took: took.to_owned(),
            tag: tag.to_owned(),
            text: text.to_owned(),
        }
    }

    /// The id is padded to the widest and the time right-aligned; a tag opens the text
    /// column, and the text's further lines stand under its first, past the tag.
    #[test]
    fn rows_align_in_columns() {
        let mut out = String::new();
        render_rows(
            &mut out,
            &[
                row("ok", "a", "1.2s", "", ""),
                row(
                    "FAIL",
                    "longer-id",
                    "12s",
                    "[Permission]  — ",
                    "denied\nby sudo",
                ),
                row("skip", "c", "", "— ", "aborted"),
            ],
        );
        assert_eq!(
            out,
            "  ok    a          1.2s\n\
             \x20 FAIL  longer-id   12s  [Permission]  — denied\n\
             \x20                                        by sudo\n\
             \x20 skip  c                — aborted\n"
        );
        // with no time in any row, there is no column for one
        let mut out = String::new();
        render_rows(
            &mut out,
            &[row("skip", "x", "", "", "why"), row("ok", "yy", "", "", "")],
        );
        assert_eq!(out, "  skip  x   why\n  ok    yy\n");
    }
}
