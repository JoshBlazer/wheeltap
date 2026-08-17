//! GitHub Actions workflow commands, for inline pull-request annotations.
//!
//! SARIF is the better channel — it produces persistent, deduplicated alerts —
//! but uploading it needs `security-events: write` and code scanning enabled,
//! which a fork PR or a repository on a plan without GitHub Advanced Security
//! does not have. Workflow commands need nothing. Emitting both means the
//! annotations always appear and the alerts appear where they can.
//!
//! # Path resolution
//!
//! GitHub places an annotation in the diff by matching `file=` against a path
//! relative to the *repository* root. A finding's path is relative to the
//! *scanned* root, so scanning `programs/` yields `vault/src/lib.rs` where the
//! repository knows `programs/vault/src/lib.rs`. Rendering takes the scanned
//! base and re-joins it. Getting this wrong does not fail loudly: the
//! annotation still prints, it just silently stops landing on the diff.
//!
//! # Escaping
//!
//! Workflow commands are line-oriented and delimited by `,` and `::`, so a
//! message containing either would truncate the command or invent a property.
//! Data is percent-escaped, and property values escape more than message
//! bodies do. Rust code is full of commas and colons; this is not a corner case.
//!
//! # Display limit
//!
//! GitHub renders at most ten annotations of each level per step. Everything is
//! emitted regardless — the log and the SARIF upload are complete — but a scan
//! with fifty findings will not show fifty bubbles. This is a limit of the
//! medium, and the reason SARIF remains the primary channel.

use std::path::Path;

use crate::path::repo_relative;
use wheeltap_core::diag::{Diagnostic, Level};
use wheeltap_core::engine::Report;
use wheeltap_core::finding::{Finding, Severity};

/// Render a report as GitHub Actions workflow commands.
///
/// `base` is the path that was scanned, relative to the repository root; it is
/// prefixed onto each finding's path. Pass `Path::new("")` or `"."` when the
/// scan ran at the repository root.
#[must_use]
pub fn render(report: &Report, base: &Path) -> String {
    let mut out = String::new();

    for finding in &report.findings {
        out.push_str(&annotation(finding, base));
        out.push('\n');
    }

    // A file that failed to parse is a hole in the scan's coverage. Reporting
    // findings while staying quiet about the code we never read would let a
    // green check mean less than it appears to.
    for diagnostic in &report.diagnostics {
        out.push_str(&diagnostic_annotation(diagnostic, base));
        out.push('\n');
    }

    out
}

fn annotation(finding: &Finding, base: &Path) -> String {
    let mut command = format!("::{} ", level(finding.severity));

    let mut properties = vec![
        format!(
            "file={}",
            escape_property(&repo_relative(base, &finding.file))
        ),
        format!("line={}", finding.line),
        format!("col={}", finding.column),
        format!(
            "title={}",
            escape_property(&format!("{} {}", finding.rule, finding.severity))
        ),
    ];
    // A finding on one line needs no end, and omitting it keeps the command
    // short enough to read in a raw log.
    if finding.location.end.line > finding.line {
        properties.push(format!("endLine={}", finding.location.end.line));
    }

    command.push_str(&properties.join(","));
    command.push_str("::");
    command.push_str(&escape_data(&body(finding)));
    command
}

/// The annotation body: what is wrong, what to do, and the identity.
///
/// The identity is included because it is what someone pastes into a baseline
/// or a `wheeltap:allow` comment, and an annotation is where they are looking
/// when they decide to.
fn body(finding: &Finding) -> String {
    format!(
        "{}\n\nFix: {}\n\nconfidence {} · id {}",
        finding.message, finding.remediation, finding.confidence, finding.id
    )
}

fn diagnostic_annotation(diagnostic: &Diagnostic, base: &Path) -> String {
    let level = match diagnostic.level {
        Level::Warning => "warning",
        Level::Error => "error",
    };
    let path = repo_relative(base, &diagnostic.path.display().to_string());

    let mut properties = vec![format!("file={}", escape_property(&path))];
    if let Some(line) = diagnostic.line {
        properties.push(format!("line={line}"));
    }
    properties.push(format!(
        "title={}",
        escape_property("Wheeltap coverage gap")
    ));

    format!(
        "::{level} {}::{}",
        properties.join(","),
        escape_data(&format!("not analysed: {}", diagnostic.message))
    )
}

/// Map severity onto the three annotation levels GitHub has.
///
/// Five levels do not fit in three, so the mapping loses information. It is
/// recovered in the title, which carries the real severity, and in SARIF's
/// `security-severity`, which carries it as a number.
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "notice",
    }
}

/// Escape a command's message body.
///
/// A literal newline would end the command, and `%` is the escape character
/// itself, so it must go first or it would double-escape the others.
fn escape_data(text: &str) -> String {
    text.replace('%', "%25")
        .replace('\r', "%0D")
        .replace('\n', "%0A")
}

/// Escape a property value, which lives inside the comma-separated list.
///
/// A comma would start a new property and a colon could close the command
/// early, so both are escaped on top of the message-body rules.
fn escape_property(text: &str) -> String {
    escape_data(text).replace(':', "%3A").replace(',', "%2C")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::{report_with, sample_finding};

    #[test]
    fn a_clean_report_emits_nothing() {
        let report = Report {
            files_scanned: 3,
            lines_scanned: 120,
            ..Report::default()
        };
        assert_eq!(render(&report, Path::new(".")), "");
    }

    #[test]
    fn a_finding_becomes_a_positioned_annotation() {
        let output = render(&report_with(&[Severity::Critical]), Path::new("."));

        assert!(output.starts_with("::error "), "critical is an error");
        assert!(output.contains("file=programs/vault/src/lib.rs"));
        assert!(output.contains("line=37"));
        assert!(output.contains("col=9"));
        assert!(output.ends_with('\n'), "one command per line");
    }

    #[test]
    fn severity_maps_onto_the_three_levels_github_has() {
        assert_eq!(level(Severity::Critical), "error");
        assert_eq!(level(Severity::High), "error");
        assert_eq!(level(Severity::Medium), "warning");
        assert_eq!(level(Severity::Low), "warning");
        assert_eq!(level(Severity::Info), "notice");
    }

    /// The real severity has to survive the squeeze into three levels, or a
    /// critical and a high finding become indistinguishable in the UI.
    #[test]
    fn the_title_carries_the_severity_the_level_could_not() {
        let output = render(&report_with(&[Severity::Critical]), Path::new("."));
        assert!(output.contains("title=WT001 critical"));
    }

    #[test]
    fn the_scanned_base_is_prefixed_so_annotations_land_on_the_diff() {
        let output = render(&report_with(&[Severity::High]), Path::new("programs"));
        assert!(
            output.contains("file=programs/programs/vault/src/lib.rs"),
            "the base joins onto the finding's own relative path: {output}"
        );
    }

    #[test]
    fn a_root_scan_needs_no_prefix() {
        for base in ["", ".", "./"] {
            let output = render(&report_with(&[Severity::High]), Path::new(base));
            assert!(
                output.contains("file=programs/vault/src/lib.rs"),
                "base {base:?} should not prefix anything: {output}"
            );
        }
    }

    /// Rust is full of commas and colons. If they are not escaped the command
    /// is truncated or grows a property that was never intended.
    #[test]
    fn commas_and_colons_cannot_break_out_of_a_property() {
        let escaped = escape_property("Vault::Withdraw, authority");
        assert!(!escaped.contains(','), "{escaped}");
        assert!(!escaped.contains(':'), "{escaped}");
        assert_eq!(escaped, "Vault%3A%3AWithdraw%2C authority");
    }

    #[test]
    fn newlines_are_encoded_rather_than_ending_the_command() {
        assert_eq!(escape_data("one\ntwo\r\n"), "one%0Atwo%0D%0A");
    }

    /// `%` is the escape character, so escaping it after the others would
    /// corrupt them: `\n` would become `%250A` and print literally.
    #[test]
    fn the_escape_character_is_escaped_first() {
        assert_eq!(escape_data("100%\n"), "100%25%0A");
    }

    #[test]
    fn a_multi_line_message_stays_on_one_line() {
        let output = render(&report_with(&[Severity::High]), Path::new("."));
        assert_eq!(output.lines().count(), 1, "one finding, one line: {output}");
    }

    #[test]
    fn the_body_carries_the_fix_and_the_identity() {
        let finding = sample_finding("WT001", Severity::High);
        let body = body(&finding);

        assert!(body.contains("Fix: "), "remediation is inline");
        assert!(
            body.contains(finding.id.as_str()),
            "the id is what gets pasted into a baseline or an allow comment"
        );
    }

    /// A parse failure is code Wheeltap did not read. Staying silent about it
    /// would make a clean run look more complete than it is.
    #[test]
    fn coverage_gaps_are_annotated_too() {
        let mut report = Report::default();
        report
            .diagnostics
            .push(Diagnostic::warning("vault/src/lib.rs", "expected `}`").at_line(42));

        let output = render(&report, Path::new("programs"));
        assert!(output.contains("::warning "));
        assert!(output.contains("file=programs/vault/src/lib.rs"));
        assert!(output.contains("line=42"));
        assert!(output.contains("not analysed"));
    }

    #[test]
    fn output_is_stable_across_runs() {
        let report = report_with(&[Severity::Critical, Severity::High]);
        assert_eq!(
            render(&report, Path::new(".")),
            render(&report, Path::new("."))
        );
    }
}
