//! JSON output.
//!
//! This is the machine-readable format and the one `--baseline` reads back in
//! Phase 4, so its stability matters more than its prettiness. Two properties
//! are load-bearing:
//!
//! - **Byte-identical across runs** over identical input (build spec invariant
//!   4). Findings arrive from the engine already sorted into a total order.
//! - **Versioned.** A consumer that pins `schema` can be told when the shape
//!   changes rather than discovering it at three in the morning.

use serde::Serialize;
use wheeltap_core::diag::Diagnostic;
use wheeltap_core::engine::Report;
use wheeltap_core::finding::{Finding, Severity};

/// Output schema version. Bump on any breaking change to the shape below, and
/// record the change in `DECISIONS.md`.
pub const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Serialize)]
pub struct JsonReport<'a> {
    pub schema: &'static str,
    pub tool: Tool,
    pub summary: Summary,
    pub findings: &'a [Finding],
    /// Files the scan could not analyse. Reported alongside findings rather
    /// than hidden: a clean result over code that failed to parse is not a
    /// clean result.
    pub diagnostics: &'a [Diagnostic],
}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub name: &'static str,
    pub version: &'static str,
}

#[derive(Debug, Serialize)]
pub struct Summary {
    pub files_scanned: usize,
    pub lines_scanned: usize,
    pub findings: usize,
    /// Counts by severity, worst first. Severities with no findings are omitted.
    pub by_severity: Vec<SeverityCount>,
}

#[derive(Debug, Serialize)]
pub struct SeverityCount {
    pub severity: Severity,
    pub count: usize,
}

/// Build the JSON view of a report.
#[must_use]
pub fn build(report: &Report) -> JsonReport<'_> {
    JsonReport {
        schema: SCHEMA_VERSION,
        tool: Tool {
            name: "wheeltap",
            version: env!("CARGO_PKG_VERSION"),
        },
        summary: Summary {
            files_scanned: report.files_scanned,
            lines_scanned: report.lines_scanned,
            findings: report.findings.len(),
            by_severity: report
                .counts()
                .into_iter()
                .map(|(severity, count)| SeverityCount { severity, count })
                .collect(),
        },
        findings: &report.findings,
        diagnostics: &report.diagnostics,
    }
}

/// Render a report as pretty-printed JSON.
///
/// # Errors
///
/// Propagates a `serde_json` failure, which in practice means a finding
/// contained a string that could not be represented.
pub fn render(report: &Report) -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(&build(report))?;
    text.push('\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use wheeltap_core::LineCol;
    use wheeltap_core::finding::{Confidence, FindingId};
    use wheeltap_core::source::{FileId, Location};

    fn finding(rule: &'static str, severity: Severity) -> Finding {
        Finding {
            id: FindingId::new(rule, "lib.rs", "m::S.f", "code"),
            rule,
            severity,
            confidence: Confidence::High,
            message: "something is wrong".into(),
            location: Location {
                file: FileId(0),
                start: LineCol { line: 3, column: 5 },
                end: LineCol { line: 3, column: 9 },
            },
            file: "lib.rs".into(),
            line: 3,
            column: 5,
            item_path: "m::S.f".into(),
            snippet: "code".into(),
            remediation: "do it differently".into(),
            references: vec!["https://example.invalid".into()],
        }
    }

    fn report() -> Report {
        Report {
            findings: vec![
                finding("WT001", Severity::Critical),
                finding("WT003", Severity::High),
            ],
            diagnostics: Vec::new(),
            files_scanned: 4,
            lines_scanned: 200,
        }
    }

    #[test]
    fn renders_a_summary_and_the_findings() {
        let text = render(&report()).expect("render");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

        assert_eq!(value["schema"], SCHEMA_VERSION);
        assert_eq!(value["tool"]["name"], "wheeltap");
        assert_eq!(value["summary"]["files_scanned"], 4);
        assert_eq!(value["summary"]["findings"], 2);
        assert_eq!(value["findings"][0]["rule"], "WT001");
        assert_eq!(value["findings"][0]["severity"], "critical");
        assert_eq!(value["findings"][0]["confidence"], "high");
        assert_eq!(value["findings"][0]["line"], 3);
    }

    #[test]
    fn severity_counts_are_worst_first_and_omit_empty_levels() {
        let text = render(&report()).expect("render");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        let counts = value["summary"]["by_severity"].as_array().expect("array");

        assert_eq!(counts.len(), 2, "medium, low and info are omitted");
        assert_eq!(counts[0]["severity"], "critical");
        assert_eq!(counts[1]["severity"], "high");
    }

    /// Build spec invariant 4.
    #[test]
    fn output_is_byte_identical_across_runs() {
        assert_eq!(
            render(&report()).expect("render"),
            render(&report()).expect("render")
        );
    }

    #[test]
    fn an_empty_report_is_still_valid_json() {
        let text = render(&Report::default()).expect("render");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        assert_eq!(value["summary"]["findings"], 0);
        assert!(value["findings"].as_array().expect("array").is_empty());
    }

    /// Identity is content-addressed and must never leak a line number.
    #[test]
    fn finding_identity_is_present_and_independent_of_position() {
        let text = render(&report()).expect("render");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");
        let id = value["findings"][0]["id"].as_str().expect("id present");

        assert_eq!(id.len(), 16);
        assert_eq!(
            id,
            FindingId::new("WT001", "lib.rs", "m::S.f", "code").as_str()
        );
    }
}
