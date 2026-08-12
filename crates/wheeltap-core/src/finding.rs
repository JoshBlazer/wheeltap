//! Findings, and the deterministic identity that makes baselines work.
//!
//! # Why identity is not a line number
//!
//! Line numbers move when unrelated code is edited. If a finding is identified
//! by where it sits, then adding an import at the top of a file changes every
//! identity below it, every run-over-run diff is noise, and `--baseline` is
//! worthless — which is the same as having no adoption path for an existing
//! codebase.
//!
//! A finding is therefore identified by *what it is* (build spec §4.3):
//!
//! ```text
//! id = hash(rule_id, relative_path, enclosing_item_path, normalised_snippet)
//! ```
//!
//! The two properties that follow are the ones the tests assert:
//!
//! - Move the offending code within its file, or edit anything around it, and
//!   the identity **survives**.
//! - Change the offending code itself, and the identity **changes** — because it
//!   is no longer the same finding, and a reviewer should look again.

use serde::{Deserialize, Serialize};

use crate::source::Location;

/// Impact if the finding is real and reachable.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Critical => "critical",
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
            Self::Info => "info",
        }
    }
}

impl std::str::FromStr for Severity {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s.to_ascii_lowercase().as_str() {
            "critical" => Ok(Self::Critical),
            "high" => Ok(Self::High),
            "medium" => Ok(Self::Medium),
            "low" => Ok(Self::Low),
            "info" => Ok(Self::Info),
            other => Err(format!("unknown severity `{other}`")),
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How sure Wheeltap is that it read the code correctly.
///
/// This is a statement about the **analyser**, not about the vulnerability.
/// Severity and confidence are different axes and are never collapsed into one
/// number: a Critical at Low confidence is worth a human minute, a Low at High
/// confidence is a lint fix.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    Low,
    Medium,
    High,
}

impl Confidence {
    #[must_use]
    pub fn as_str(self) -> &'static str {
        match self {
            Self::High => "high",
            Self::Medium => "medium",
            Self::Low => "low",
        }
    }
}

impl std::fmt::Display for Confidence {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A finding's stable identity. See the module documentation.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct FindingId(pub String);

impl FindingId {
    /// Compute an identity from the four components in build spec §4.3.
    #[must_use]
    pub fn new(rule: &str, relative_path: &str, item_path: &str, snippet: &str) -> Self {
        Self(crate::short_hash(&[
            rule,
            relative_path,
            item_path,
            &normalise_snippet(snippet),
        ]))
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for FindingId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reduce a snippet to the code that matters for identity.
///
/// Comments are stripped and whitespace collapsed, so that reformatting, adding
/// a clarifying comment, or re-indenting does not invent a "new" finding. What
/// remains is the tokens themselves — change those and the identity changes,
/// which is the intent.
#[must_use]
pub fn normalise_snippet(snippet: &str) -> String {
    let mut out = String::with_capacity(snippet.len());
    let mut chars = snippet.chars().peekable();
    let mut in_block_comment = false;

    while let Some(ch) = chars.next() {
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                chars.next();
                in_block_comment = false;
            }
            continue;
        }

        match ch {
            '/' if chars.peek() == Some(&'/') => {
                // Line comment: discard to end of line.
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
                out.push(' ');
            }
            '/' if chars.peek() == Some(&'*') => {
                chars.next();
                in_block_comment = true;
                out.push(' ');
            }
            c if c.is_whitespace() => out.push(' '),
            c => out.push(c),
        }
    }

    out.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// One reported problem.
#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub id: FindingId,
    pub rule: &'static str,
    pub severity: Severity,
    pub confidence: Confidence,
    /// What is wrong, specifically. Names the account or value involved.
    pub message: String,
    /// Where to look. Presentation only — never part of identity.
    #[serde(skip)]
    pub location: Location,
    pub file: String,
    pub line: usize,
    pub column: usize,
    /// The enclosing item, e.g. `vault::Withdraw.authority`.
    pub item_path: String,
    pub snippet: String,
    pub remediation: String,
    pub references: Vec<String>,
    /// Lines on which an inline `wheeltap:allow` would cover this finding: its
    /// own line, plus the run of attributes and comments directly above it.
    /// Presentation-free and not part of identity, so it is not serialised.
    #[serde(skip)]
    pub suppression_lines: Vec<usize>,
}

impl Finding {
    /// Order findings for output.
    ///
    /// Deterministic and severity-first: the reader should meet the worst
    /// problem before the least, and two runs must agree byte for byte
    /// (invariant 4). Ties break on position, then rule, then identity — so the
    /// ordering is total, with no dependence on the order detectors ran.
    #[must_use]
    pub fn ordering_key(&self) -> impl Ord + '_ {
        (
            std::cmp::Reverse(self.severity),
            &self.file,
            self.line,
            self.column,
            self.rule,
            self.id.as_str(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn severity_orders_by_impact() {
        assert!(Severity::Critical > Severity::High);
        assert!(Severity::High > Severity::Medium);
        assert!(Severity::Low > Severity::Info);
        assert_eq!("critical".parse(), Ok(Severity::Critical));
        assert_eq!("HIGH".parse(), Ok(Severity::High));
        assert!("catastrophic".parse::<Severity>().is_err());
    }

    #[test]
    fn normalisation_strips_comments_and_collapses_whitespace() {
        assert_eq!(
            normalise_snippet("pub authority:   AccountInfo<'info>,   // unchecked"),
            "pub authority: AccountInfo<'info>,"
        );
        assert_eq!(
            normalise_snippet("let a = /* inline */ b + c;"),
            "let a = b + c;"
        );
        assert_eq!(
            normalise_snippet("a\n    +\n    b"),
            "a + b",
            "reformatting must not change identity"
        );
    }

    #[test]
    fn an_unterminated_block_comment_does_not_hang_or_panic() {
        assert_eq!(normalise_snippet("code /* never closed"), "code");
    }

    /// The property the whole scheme exists for.
    #[test]
    fn identity_survives_movement_and_reformatting() {
        let at_top = FindingId::new(
            "WT001",
            "programs/vault/src/lib.rs",
            "vault::Withdraw.authority",
            "pub authority: AccountInfo<'info>,",
        );
        let moved_and_reformatted = FindingId::new(
            "WT001",
            "programs/vault/src/lib.rs",
            "vault::Withdraw.authority",
            "  pub authority:  AccountInfo<'info>,  // moved down 40 lines\n",
        );
        assert_eq!(at_top, moved_and_reformatted);
    }

    #[test]
    fn identity_changes_when_the_offending_code_changes() {
        let before = FindingId::new(
            "WT001",
            "programs/vault/src/lib.rs",
            "vault::Withdraw.authority",
            "pub authority: AccountInfo<'info>,",
        );
        let after = FindingId::new(
            "WT001",
            "programs/vault/src/lib.rs",
            "vault::Withdraw.authority",
            "pub authority: Signer<'info>,",
        );
        assert_ne!(before, after);
    }

    #[test]
    fn identity_distinguishes_rule_path_and_item() {
        let base = FindingId::new("WT001", "a.rs", "m::S.f", "code");
        assert_ne!(base, FindingId::new("WT002", "a.rs", "m::S.f", "code"));
        assert_ne!(base, FindingId::new("WT001", "b.rs", "m::S.f", "code"));
        assert_ne!(base, FindingId::new("WT001", "a.rs", "m::S.g", "code"));
    }

    /// Two identical-looking fields in different structs are different
    /// findings, and the item path is what separates them.
    #[test]
    fn identical_code_in_different_items_gets_different_identities() {
        let withdraw = FindingId::new(
            "WT001",
            "lib.rs",
            "vault::Withdraw.authority",
            "pub authority: AccountInfo<'info>,",
        );
        let close = FindingId::new(
            "WT001",
            "lib.rs",
            "vault::Close.authority",
            "pub authority: AccountInfo<'info>,",
        );
        assert_ne!(withdraw, close);
    }
}
