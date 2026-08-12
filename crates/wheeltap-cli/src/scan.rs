//! `wheeltap scan` — analyse a path and report findings.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use wheeltap_core::ProgramContext;
use wheeltap_core::baseline::Baseline;
use wheeltap_core::engine::{self, Report};
use wheeltap_core::finding::Severity;
use wheeltap_core::suppress::{Config, Suppressor};
use wheeltap_report::Format;

use crate::{EXIT_CLEAN, EXIT_ERROR, EXIT_FINDINGS};

pub struct Options<'a> {
    pub path: &'a Path,
    pub format: Format,
    /// Findings below this severity are not reported at all.
    pub severity_threshold: Severity,
    /// Findings at or above this severity make the command exit 1.
    pub fail_on: Severity,
    /// Report only findings absent from this previous JSON report.
    pub baseline: Option<PathBuf>,
    /// Explicit config path; otherwise `wheeltap.toml` beside the scanned path.
    pub config: Option<PathBuf>,
    /// Ignore `wheeltap.toml` and inline `wheeltap:allow` comments entirely.
    pub no_suppress: bool,
}

pub fn run(options: &Options<'_>) -> ExitCode {
    if !options.path.exists() {
        eprintln!(
            "wheeltap: {}: no such file or directory",
            options.path.display()
        );
        return ExitCode::from(EXIT_ERROR);
    }

    let config = match load_config(options) {
        Ok(config) => config,
        Err(message) => {
            eprintln!("wheeltap: {message}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    let baseline = match options.baseline.as_deref().map(Baseline::load).transpose() {
        Ok(baseline) => baseline,
        Err(err) => {
            eprintln!("wheeltap: {err}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    // Analysis runs on a thread with a stack of its own; the report is plain
    // data and crosses back, the context is not `Send` and stays there (ADR-005).
    let path = options.path;
    let threshold = options.severity_threshold;
    let no_suppress = options.no_suppress;
    let (mut report, looks_like_anchor) = wheeltap_core::loader::with_analysis_stack(move || {
        let ctx = ProgramContext::scan(path);
        let anchor = ctx.looks_like_anchor();
        let mut report = engine::run(&ctx, &wheeltap_rules::all());

        if !no_suppress {
            let suppressor = Suppressor::new(config, &ctx.sources);
            let (kept, warnings) = suppressor.apply(std::mem::take(&mut report.findings));
            report.findings = kept;
            report.diagnostics.extend(warnings);
        }

        // The threshold filters after suppression, so a downgraded severity is
        // measured at its new level rather than its original one.
        report.findings.retain(|f| f.severity >= threshold);
        (report, anchor)
    });

    if let Some(baseline) = &baseline {
        let before = report.findings.len();
        report.findings = baseline.filter_new(std::mem::take(&mut report.findings));
        eprintln!(
            "wheeltap: baseline holds {} finding(s); {} of {} suppressed as pre-existing",
            baseline.len(),
            before - report.findings.len(),
            before
        );
    }

    let text = match render(options.format, &report) {
        Ok(text) => text,
        Err(message) => {
            eprintln!("wheeltap: {message}");
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

/// Load configuration, from an explicit path or by convention.
///
/// An explicit `--config` that does not exist is an error; a missing
/// `wheeltap.toml` is not, because most projects have none.
fn load_config(options: &Options<'_>) -> Result<Config, String> {
    if options.no_suppress {
        return Ok(Config::default());
    }

    if let Some(path) = &options.config {
        let text = std::fs::read_to_string(path)
            .map_err(|err| format!("could not read {}: {err}", path.display()))?;
        return Config::parse(&text)
            .map_err(|err| format!("could not parse {}: {err}", path.display()));
    }

    // By convention, beside the scanned path — or beside its parent when a
    // single file was named.
    let dir = if options.path.is_dir() {
        options.path.to_path_buf()
    } else {
        options
            .path
            .parent()
            .unwrap_or(Path::new("."))
            .to_path_buf()
    };

    Config::load(&dir)
        .map(Option::unwrap_or_default)
        .map_err(|err| err.to_string())
}

fn render(format: Format, report: &Report) -> Result<String, String> {
    match format {
        Format::Json => wheeltap_report::json::render(report)
            .map_err(|err| format!("could not serialise the report: {err}")),
        Format::Markdown => Ok(wheeltap_report::markdown::render(report)),
        Format::Sarif => {
            let rules: Vec<_> = wheeltap_rules::all()
                .iter()
                .map(|detector| detector.metadata())
                .collect();
            wheeltap_report::sarif::render(report, &rules)
                .map_err(|err| format!("could not serialise SARIF: {err}"))
        }
    }
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
                    suppression_lines: vec![1],
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

    #[test]
    fn every_format_renders() {
        let report = report_with(&[Severity::Critical]);
        for format in [Format::Json, Format::Markdown, Format::Sarif] {
            let text = render(format, &report)
                .unwrap_or_else(|err| panic!("{} failed: {err}", format.as_str()));
            assert!(!text.is_empty(), "{} produced nothing", format.as_str());
        }
    }
}
