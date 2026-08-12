//! Shared fixtures for the reporter tests.
//!
//! Building a `Finding` by hand is verbose, and three reporters need the same
//! ones. Kept here so a change to the finding shape updates one place.

#![cfg(test)]

use wheeltap_core::LineCol;
use wheeltap_core::RuleMetadata;
use wheeltap_core::engine::Report;
use wheeltap_core::finding::{Confidence, Finding, FindingId, Severity};
use wheeltap_core::source::{FileId, Location};

const RULES: [&str; 4] = ["WT001", "WT002", "WT003", "WT004"];

pub fn sample_finding(rule: &'static str, severity: Severity) -> Finding {
    let file = "programs/vault/src/lib.rs";
    let item_path = "vault::Withdraw.authority";
    let snippet = "    pub authority: AccountInfo<'info>,";

    Finding {
        id: FindingId::new(rule, file, item_path, snippet),
        rule,
        severity,
        confidence: Confidence::High,
        message: format!("{rule}: the authority is never required to sign"),
        location: Location {
            file: FileId(0),
            start: LineCol {
                line: 37,
                column: 9,
            },
            end: LineCol {
                line: 37,
                column: 42,
            },
        },
        file: file.into(),
        line: 37,
        column: 9,
        item_path: item_path.into(),
        snippet: snippet.into(),
        remediation: "Type the account as `Signer<'info>`.".into(),
        references: vec!["https://example.invalid/wt001".into()],
        suppression_lines: vec![36, 37],
    }
}

/// A report holding one finding per severity given, ordered as the engine
/// would order them.
pub fn report_with(severities: &[Severity]) -> Report {
    let mut findings: Vec<Finding> = severities
        .iter()
        .enumerate()
        .map(|(index, severity)| sample_finding(RULES[index % RULES.len()], *severity))
        .collect();
    findings.sort_by(|a, b| a.ordering_key().cmp(&b.ordering_key()));

    Report {
        findings,
        diagnostics: Vec::new(),
        files_scanned: 4,
        lines_scanned: 200,
    }
}

/// Rule metadata for the four rules `report_with` draws from.
pub fn sample_rules() -> Vec<RuleMetadata> {
    RULES
        .iter()
        .map(|id| RuleMetadata {
            id,
            name: "Sample rule",
            severity: Severity::High,
            confidence: Confidence::High,
            description: "a rule used in tests",
            remediation: "do the other thing",
            references: &["https://example.invalid/rule"],
        })
        .collect()
}
