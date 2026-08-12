//! `wheeltap scan` — analyse a path and report findings.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use wheeltap_core::ProgramContext;
use wheeltap_core::engine::{self, Report};
use wheeltap_core::finding::Severity;
use wheeltap_report::Format;

use crate::{EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS};

pub struct Options<'a> {
    pub path: &'a Path,
    pub format: Format,
    /// Findings below this severity are not reported at all.
    pub severity_threshold: Severity,
    /// Findings at or above this severity make the command exit 1.
    pub fail_on: Severity,
}

pub fn run(options: &Options<'_>) -> ExitCode {
    if !options.path.exists() {
        eprintln!(
            "wheeltap: {}: no such file or directory",
            options.path.display()
        );
        return ExitCode::from(EXIT_ERROR);
    }

    // Analysis runs on a thread with a stack of its own; the report is plain
    // data and crosses back, the context is not `Send` and stays there (ADR-005).
    let path = options.path;
    let threshold = options.severity_threshold;
    let mut report = wheeltap_core::loader::with_analysis_stack(move || {
        let ctx = ProgramContext::scan(path);
        let anchor = ctx.looks_like_anchor();
        let mut report = engine::run(&ctx, &wheeltap_rules::all());
        report.findings.retain(|f| f.severity >= threshold);
        (report, anchor)
    });

    let looks_like_anchor = report.1;
    let report = std::mem::take(&mut report.0);

    let text = match options.format {
        Format::Json => match wheeltap_report::json::render(&report) {
            Ok(text) => text,
            Err(err) => {
                eprintln!("wheeltap: could not serialise the report: {err}");
                return ExitCode::from(EXIT_ERROR);
            }
        },
        Format::Markdown | Format::Sarif => {
            eprintln!(
                "wheeltap: the `{}` reporter is not implemented yet (arrives in Phase 4).",
                options.format.as_str()
            );
            return ExitCode::from(EXIT_ERROR);
        }
    };

    if let Err(err) = write(&mut io::stdout().lock(), &text) {
        return crate::write_failure(&err);
    }

    if report.files_scanned == 0 {
        eprintln!(
            "wheeltap: no Rust source found under {}",
            options.path.display()
        );
        return ExitCode::from(EXIT_ERROR);
    }

    // A scan that found no Anchor code at all almost certainly points at the
    // wrong directory. Reporting a confident zero would be worse than useless.
    if !looks_like_anchor {
        eprintln!(
            "wheeltap: warning: no #[program] module or #[derive(Accounts)] struct found under {}; \
             this may not be an Anchor program.",
            options.path.display()
        );
    }

    for diagnostic in &report.diagnostics {
        eprintln!("wheeltap: {diagnostic}");
    }

    ExitCode::from(exit_code_for(&report, options.fail_on))
}

fn write(out: &mut impl Write, text: &str) -> io::Result<()> {
    out.write_all(text.as_bytes())?;
    out.flush()
}

/// Whether a report should fail the build, given a threshold.
///
/// Extracted so the exit-code contract can be tested without a filesystem.
#[must_use]
pub fn exit_code_for(report: &Report, fail_on: Severity) -> u8 {
    if report.has_findings_at_or_above(fail_on) {
        EXIT_FINDINGS
    } else {
        EXIT_CLEAN
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wheeltap_core::LineCol;
    use wheeltap_core::finding::{Confidence, Finding, FindingId};
    use wheeltap_core::source::{FileId, Location};

    fn report_with(severities: &[Severity]) -> Report {
        Report {
            findings: severities
                .iter()
                .enumerate()
                .map(|(i, severity)| Finding {
                    id: FindingId::new("WT001", "lib.rs", &format!("m::S.f{i}"), "code"),
                    rule: "WT001",
                    severity: *severity,
                    confidence: Confidence::High,
                    message: "wrong".into(),
                    location: Location {
                        file: FileId(0),
                        start: LineCol { line: 1, column: 1 },
                        end: LineCol { line: 1, column: 2 },
                    },
                    file: "lib.rs".into(),
                    line: 1,
                    column: 1,
                    item_path: format!("m::S.f{i}"),
                    snippet: "code".into(),
                    remediation: "fix".into(),
                    references: vec![],
                })
                .collect(),
            ..Report::default()
        }
    }

    #[test]
    fn a_clean_scan_exits_zero() {
        assert_eq!(exit_code_for(&report_with(&[]), Severity::Low), EXIT_CLEAN);
    }

    #[test]
    fn findings_at_or_above_the_threshold_exit_one() {
        let report = report_with(&[Severity::High]);
        assert_eq!(exit_code_for(&report, Severity::High), EXIT_FINDINGS);
        assert_eq!(exit_code_for(&report, Severity::Medium), EXIT_FINDINGS);
    }

    #[test]
    fn findings_below_the_threshold_do_not_fail_the_build() {
        let report = report_with(&[Severity::Low, Severity::Info]);
        assert_eq!(exit_code_for(&report, Severity::High), EXIT_CLEAN);
    }
}
