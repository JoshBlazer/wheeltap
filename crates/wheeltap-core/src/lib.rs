//! Core types and analysis machinery for Wheeltap.
//!
//! The pipeline runs [`loader`] → [`model`] → detectors:
//!
//! - [`loader`] discovers and parses source, degrading parse failures to
//!   [`diag`] warnings rather than aborting the scan.
//! - [`source`] maps `syn` spans back to files, lines, and snippets.
//! - [`model`] turns the AST into an Anchor-aware [`model::ProgramContext`].
//! - [`summary`] projects that model onto serialisable data for
//!   `wheeltap debug-context` and snapshot tests.
//! - [`engine`] runs [`Detector`]s over the model and assembles a report.
//! - [`finding`] defines what a detector reports, including the deterministic
//!   identity that makes run-over-run baselines possible.
//!
//! The detectors themselves live in `wheeltap-rules`, which depends on this
//! crate; the engine takes them as a parameter so the dependency stays one-way.

pub mod baseline;
pub mod diag;
pub mod engine;
pub mod finding;
pub mod loader;
pub mod model;
pub mod source;
pub mod summary;
pub mod suppress;

pub use engine::{Detector, RuleMetadata};
pub use finding::{Confidence, Finding, FindingId, Severity};
pub use model::ProgramContext;

use sha2::{Digest, Sha256};

/// A zero-indexed byte position resolved to a human-facing line and column.
///
/// Lines and columns are 1-indexed, matching every editor and SARIF itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LineCol {
    pub line: usize,
    pub column: usize,
}

/// Resolve a `proc_macro2` span to a 1-indexed line and column.
///
/// Requires `proc-macro2`'s `span-locations` feature, which reports real
/// positions only outside a procedural macro context. Wheeltap is a CLI, so
/// this always holds.
#[must_use]
pub fn span_start(span: proc_macro2::Span) -> LineCol {
    let start = span.start();
    LineCol {
        line: start.line,
        column: start.column + 1,
    }
}

/// Hash bytes to a lowercase hex digest, truncated to 16 characters.
///
/// Sixteen hex characters is 64 bits: ample against collision for the number
/// of findings a single scan produces, and short enough to read in a diff.
#[must_use]
pub fn short_hash(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        // Length-prefix each part so that ("ab", "c") and ("a", "bc") differ.
        hasher.update(part.len().to_le_bytes());
        hasher.update(part.as_bytes());
    }
    let digest = hasher.finalize();
    digest.iter().take(8).fold(String::new(), |mut acc, byte| {
        use std::fmt::Write as _;
        let _ = write!(acc, "{byte:02x}");
        acc
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use syn::spanned::Spanned as _;

    /// The whole tool rests on `syn` parsing Anchor-shaped source and handing
    /// back usable spans. Prove it before building anything on top.
    #[test]
    fn parses_source_and_reports_span_locations() {
        let source = r"
#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,
}
";
        let file = syn::parse_file(source).expect("fixture must parse");
        let syn::Item::Struct(item) = &file.items[0] else {
            panic!("expected a struct item");
        };

        assert_eq!(item.ident, "Initialize");

        let field = item.fields.iter().next().expect("one field");
        assert_eq!(field.attrs.len(), 1, "the #[account] attribute survives");

        // A field's own span covers its attributes, so it starts at
        // `#[account(mut)]` on line 4 rather than at the declaration. Findings
        // about a field want the name, so detectors report `field.ident`.
        assert_eq!(span_start(field.span()).line, 4);
        let ident = field.ident.as_ref().expect("named field");
        assert_eq!(span_start(ident.span()), LineCol { line: 5, column: 9 });
    }

    /// A file that does not parse must surface as a recoverable error, never a
    /// panic. Invariant 1 in the build spec's testing strategy.
    #[test]
    fn malformed_source_errors_without_panicking() {
        let err = syn::parse_file("pub struct Broken { ").unwrap_err();
        assert!(!err.to_string().is_empty());
    }

    #[test]
    fn short_hash_is_deterministic_and_field_separated() {
        assert_eq!(
            short_hash(&["WT001", "lib.rs"]),
            short_hash(&["WT001", "lib.rs"])
        );
        assert_ne!(short_hash(&["ab", "c"]), short_hash(&["a", "bc"]));
        assert_eq!(short_hash(&["WT001"]).len(), 16);
    }
}
