//! The detector trait and the engine that runs them.
//!
//! Execution is single-threaded, deliberately: `syn` ASTs are not `Send`, and a
//! 73,000-line production protocol analyses in well under a second. ADR-005 has
//! the measurements.

use crate::finding::{Confidence, Finding, FindingId, Severity};
use crate::model::ProgramContext;
use crate::source::Location;

/// Static description of a rule, for reports and SARIF metadata.
#[derive(Debug, Clone, Copy)]
pub struct RuleMetadata {
    pub id: &'static str,
    pub name: &'static str,
    pub severity: Severity,
    /// The confidence a finding carries unless the detector says otherwise.
    pub confidence: Confidence,
    /// One line: what the rule finds.
    pub description: &'static str,
    /// What to do instead.
    pub remediation: &'static str,
    pub references: &'static [&'static str],
}

/// One security rule.
pub trait Detector: Send + Sync {
    fn rule_id(&self) -> &'static str;
    fn metadata(&self) -> RuleMetadata;
    fn check(&self, ctx: &ProgramContext) -> Vec<Finding>;
}

/// Everything a scan produced.
#[derive(Debug, Default)]
pub struct Report {
    pub findings: Vec<Finding>,
    pub diagnostics: Vec<crate::diag::Diagnostic>,
    pub files_scanned: usize,
    pub lines_scanned: usize,
}

impl Report {
    /// Whether anything at or above `threshold` was found.
    #[must_use]
    pub fn has_findings_at_or_above(&self, threshold: Severity) -> bool {
        self.findings.iter().any(|f| f.severity >= threshold)
    }

    /// Count findings by severity, worst first.
    #[must_use]
    pub fn counts(&self) -> Vec<(Severity, usize)> {
        let order = [
            Severity::Critical,
            Severity::High,
            Severity::Medium,
            Severity::Low,
            Severity::Info,
        ];
        order
            .into_iter()
            .map(|severity| {
                (
                    severity,
                    self.findings
                        .iter()
                        .filter(|f| f.severity == severity)
                        .count(),
                )
            })
            .filter(|(_, count)| *count > 0)
            .collect()
    }
}

/// Run every detector over a context and assemble the report.
///
/// Findings are deduplicated by identity — two rules describing the same defect
/// at the same place should be reported once — and sorted into a total order so
/// that two runs over identical input agree byte for byte (invariant 4).
#[must_use]
pub fn run(ctx: &ProgramContext, detectors: &[Box<dyn Detector>]) -> Report {
    let mut findings: Vec<Finding> = detectors
        .iter()
        .flat_map(|detector| detector.check(ctx))
        .collect();

    findings.sort_by(|a, b| a.ordering_key().cmp(&b.ordering_key()));
    findings.dedup_by(|a, b| a.id == b.id);

    Report {
        findings,
        diagnostics: ctx.diagnostics.clone(),
        files_scanned: ctx.sources.len(),
        lines_scanned: ctx.sources.iter().map(|f| f.line_count()).sum(),
    }
}

/// How many source lines a finding's snippet may span.
///
/// Enough to show an account field with its constraints, not so much that a
/// finding inside a long function prints the function.
const SNIPPET_LINES: usize = 6;

impl ProgramContext {
    /// Build a finding, computing its snippet and deterministic identity.
    ///
    /// Detectors go through here rather than constructing a [`Finding`]
    /// directly, so that identity is derived one way and only one way.
    #[must_use]
    pub fn finding(
        &self,
        rule: &RuleMetadata,
        at: Location,
        item_path: &str,
        message: impl Into<String>,
    ) -> Finding {
        let file = self.sources.display_path(at.file);
        let snippet = self.sources.get(at.file).snippet(at, SNIPPET_LINES);

        Finding {
            id: FindingId::new(rule.id, &file, item_path, &snippet),
            rule: rule.id,
            severity: rule.severity,
            confidence: rule.confidence,
            message: message.into(),
            location: at,
            file,
            line: at.start.line,
            column: at.start.column,
            item_path: item_path.to_string(),
            snippet,
            remediation: rule.remediation.to_string(),
            references: rule.references.iter().map(|r| (*r).to_string()).collect(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    const TEST_RULE: RuleMetadata = RuleMetadata {
        id: "WT999",
        name: "Test rule",
        severity: Severity::High,
        confidence: Confidence::High,
        description: "for tests",
        remediation: "do the other thing",
        references: &["https://example.invalid/rule"],
    };

    /// A detector that reports one finding per Accounts struct field.
    struct EveryField(Severity);

    impl Detector for EveryField {
        fn rule_id(&self) -> &'static str {
            "WT999"
        }
        fn metadata(&self) -> RuleMetadata {
            RuleMetadata {
                severity: self.0,
                ..TEST_RULE
            }
        }
        fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
            let meta = self.metadata();
            ctx.accounts
                .iter()
                .flat_map(|a| a.fields.iter())
                .map(|field| ctx.finding(&meta, field.location, &field.item_path, "test finding"))
                .collect()
        }
    }

    fn context() -> ProgramContext {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(
            dir.path().join("lib.rs"),
            "#[derive(Accounts)] pub struct A<'info> { pub one: Signer<'info>, pub two: Signer<'info> }",
        )
        .expect("write");
        // Keep the directory alive for the scan, then leak it: the context
        // holds only text it already read.
        let ctx = ProgramContext::scan(dir.path());
        drop(dir);
        ctx
    }

    #[test]
    fn the_engine_collects_findings_from_every_detector() {
        let ctx = context();
        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(EveryField(Severity::High))];
        let report = run(&ctx, &detectors);

        assert_eq!(report.findings.len(), 2);
        assert_eq!(report.files_scanned, 1);
        assert!(report.findings.iter().all(|f| f.rule == "WT999"));
    }

    #[test]
    fn identical_findings_from_two_detectors_are_deduplicated() {
        let ctx = context();
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(EveryField(Severity::High)),
            Box::new(EveryField(Severity::High)),
        ];
        assert_eq!(run(&ctx, &detectors).findings.len(), 2, "not four");
    }

    #[test]
    fn findings_are_sorted_worst_first() {
        let ctx = context();
        let detectors: Vec<Box<dyn Detector>> = vec![
            Box::new(EveryField(Severity::Low)),
            Box::new(EveryField(Severity::Critical)),
        ];
        let report = run(&ctx, &detectors);

        let severities: Vec<_> = report.findings.iter().map(|f| f.severity).collect();
        assert_eq!(severities[0], Severity::Critical);
        assert_eq!(severities.last(), Some(&Severity::Low));
    }

    #[test]
    fn threshold_and_counts_read_the_findings() {
        let ctx = context();
        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(EveryField(Severity::Medium))];
        let report = run(&ctx, &detectors);

        assert!(report.has_findings_at_or_above(Severity::Low));
        assert!(report.has_findings_at_or_above(Severity::Medium));
        assert!(!report.has_findings_at_or_above(Severity::High));
        assert_eq!(report.counts(), vec![(Severity::Medium, 2)]);
    }

    #[test]
    fn a_scan_with_no_detectors_is_clean() {
        let report = run(&context(), &[]);
        assert!(report.findings.is_empty());
        assert!(!report.has_findings_at_or_above(Severity::Info));
    }

    #[test]
    fn findings_carry_rule_metadata_through() {
        let ctx = context();
        let detectors: Vec<Box<dyn Detector>> = vec![Box::new(EveryField(Severity::High))];
        let finding = &run(&ctx, &detectors).findings[0];

        assert_eq!(finding.remediation, "do the other thing");
        assert_eq!(finding.references, ["https://example.invalid/rule"]);
        assert_eq!(finding.confidence, Confidence::High);
        assert!(finding.item_path.starts_with("A."));
    }

    #[test]
    fn scanning_nothing_produces_an_empty_report() {
        let ctx = ProgramContext::scan(Path::new("/no/such/path"));
        let report = run(&ctx, &[]);
        assert_eq!(report.files_scanned, 0);
        assert_eq!(report.diagnostics.len(), 1);
    }
}
