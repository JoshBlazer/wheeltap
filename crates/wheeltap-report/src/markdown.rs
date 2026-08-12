//! Markdown output, for humans reading a CI log or a pull request comment.
//!
//! Grouped worst-first, because the reader's attention is finite and the first
//! thing they see should be the thing that matters most. Every finding carries
//! its snippet and its remediation inline: a report that makes someone open
//! another document to learn what to do is a report they skim.

use wheeltap_core::engine::Report;
use wheeltap_core::finding::{Finding, Severity};

/// Render a report as Markdown.
#[must_use]
pub fn render(report: &Report) -> String {
    let mut out = String::new();

    out.push_str("# Wheeltap\n\n");

    if report.findings.is_empty() {
        out.push_str(&format!(
            "No findings. Scanned {} file{}, {} lines.\n",
            report.files_scanned,
            plural(report.files_scanned),
            report.lines_scanned
        ));
        render_diagnostics(&mut out, report);
        return out;
    }

    out.push_str(&format!(
        "**{} finding{}** in {} file{}, {} lines.\n\n",
        report.findings.len(),
        plural(report.findings.len()),
        report.files_scanned,
        plural(report.files_scanned),
        report.lines_scanned
    ));

    out.push_str("| Severity | Count |\n|---|---|\n");
    for (severity, count) in report.counts() {
        out.push_str(&format!("| {severity} | {count} |\n"));
    }
    out.push('\n');

    // Findings arrive from the engine already sorted worst-first, so grouping
    // is a matter of noticing where the severity changes.
    let mut current: Option<Severity> = None;
    for finding in &report.findings {
        if current != Some(finding.severity) {
            out.push_str(&format!("## {}\n\n", heading(finding.severity)));
            current = Some(finding.severity);
        }
        render_finding(&mut out, finding);
    }

    render_diagnostics(&mut out, report);
    out
}

fn render_finding(out: &mut String, finding: &Finding) {
    out.push_str(&format!(
        "### `{}` {}:{}\n\n",
        finding.rule, finding.file, finding.line
    ));
    out.push_str(&format!("{}\n\n", finding.message));

    out.push_str("```rust\n");
    out.push_str(finding.snippet.trim_end());
    out.push_str("\n```\n\n");

    out.push_str(&format!("**Fix.** {}\n\n", finding.remediation));

    out.push_str(&format!(
        "<sub>{} · confidence {} · `{}` · id `{}`</sub>\n\n",
        finding.severity, finding.confidence, finding.item_path, finding.id
    ));

    if !finding.references.is_empty() {
        out.push_str("<sub>");
        let links: Vec<String> = finding
            .references
            .iter()
            .map(|url| format!("[reference]({url})"))
            .collect();
        out.push_str(&links.join(" · "));
        out.push_str("</sub>\n\n");
    }
}

/// Diagnostics are coverage gaps, and a report that hides them can claim to be
/// clean about code it never read.
fn render_diagnostics(out: &mut String, report: &Report) {
    if report.diagnostics.is_empty() {
        return;
    }

    out.push_str(&format!(
        "## Diagnostics\n\n{} file{} could not be fully analysed.\n\n",
        report.diagnostics.len(),
        plural(report.diagnostics.len())
    ));
    for diagnostic in &report.diagnostics {
        out.push_str(&format!("- {diagnostic}\n"));
    }
    out.push('\n');
}

fn heading(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "Critical",
        Severity::High => "High",
        Severity::Medium => "Medium",
        Severity::Low => "Low",
        Severity::Info => "Info",
    }
}

fn plural(n: usize) -> &'static str {
    if n == 1 { "" } else { "s" }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::{report_with, sample_finding};

    #[test]
    fn a_clean_report_says_so_plainly() {
        let markdown = render(&Report {
            files_scanned: 3,
            lines_scanned: 120,
            ..Report::default()
        });
        assert!(markdown.contains("No findings"));
        assert!(markdown.contains("3 files, 120 lines"));
    }

    #[test]
    fn findings_are_grouped_worst_first() {
        let markdown = render(&report_with(&[Severity::Critical, Severity::Low]));

        let critical = markdown.find("## Critical").expect("critical heading");
        let low = markdown.find("## Low").expect("low heading");
        assert!(critical < low, "the worst problem comes first");
    }

    #[test]
    fn a_finding_carries_its_snippet_remediation_and_identity() {
        let markdown = render(&report_with(&[Severity::High]));

        assert!(markdown.contains("```rust"), "snippet is fenced");
        assert!(markdown.contains("**Fix.**"), "remediation is inline");
        assert!(markdown.contains("confidence high"));
        assert!(
            markdown.contains(sample_finding("WT001", Severity::High).id.as_str()),
            "identity is printed so it can be used in a baseline"
        );
    }

    #[test]
    fn diagnostics_are_reported_rather_than_hidden() {
        let mut report = report_with(&[Severity::High]);
        report
            .diagnostics
            .push(wheeltap_core::diag::Diagnostic::warning(
                "programs/broken.rs",
                "could not parse",
            ));

        let markdown = render(&report);
        assert!(markdown.contains("## Diagnostics"));
        assert!(markdown.contains("programs/broken.rs"));
    }

    #[test]
    fn output_is_stable_across_runs() {
        assert_eq!(
            render(&report_with(&[Severity::Critical, Severity::High])),
            render(&report_with(&[Severity::Critical, Severity::High]))
        );
    }
}
