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

/// An extra report to write to a file, alongside the one on stdout.
///
/// A CI run wants three views of one scan: annotations in the log, SARIF for
/// code scanning, and Markdown for the job summary. Scanning three times to get
/// them would triple the work for identical results, and — worse — three scans
/// are three chances to disagree. One scan, many renderings.
#[derive(Debug, Clone)]
pub struct Emit {
    pub format: Format,
    pub path: PathBuf,
}

impl std::str::FromStr for Emit {
    type Err = String;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (format, path) = s
            .split_once('=')
            .ok_or_else(|| format!("expected FORMAT=PATH, got `{s}`"))?;
        if path.is_empty() {
            return Err(format!("`{s}` has no path after the `=`"));
        }
        Ok(Self {
            format: format.parse()?,
            path: PathBuf::from(path),
        })
    }
}

pub struct Options<'a> {
    pub path: &'a Path,
    pub format: Format,
    /// Extra reports to write to files, in addition to stdout.
    pub emit: Vec<Emit>,
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

    // Findings carry paths relative to the scanned root. GitHub matches an
    // annotation to a diff by repository-relative path, so the renderer needs
    // the base to put back — see `wheeltap_report::github`.
    let base = annotation_base(options.path);

    let text = match render(options.format, &report, &base) {
        Ok(text) => text,
        Err(message) => {
            eprintln!("wheeltap: {message}");
            return ExitCode::from(EXIT_ERROR);
        }
    };

    // Files first: stdout may be a closed pipe, and a `--emit sarif=...` that
    // silently did not happen because someone piped to `head` would be a
    // genuinely confusing way to lose a CI artefact.
    for emit in &options.emit {
        if let Err(message) = write_emit(emit, &report, &base) {
            eprintln!("wheeltap: {message}");
            return ExitCode::from(EXIT_ERROR);
        }
    }

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

/// The prefix that turns a finding's path back into a repository-relative one.
///
/// `loader::load` roots a directory scan at the directory and a single-file
/// scan at its parent; this mirrors that, so the two cannot drift apart.
fn annotation_base(path: &Path) -> PathBuf {
    if path.is_file() {
        path.parent().unwrap_or(Path::new(".")).to_path_buf()
    } else {
        path.to_path_buf()
    }
}

fn write_emit(emit: &Emit, report: &Report, base: &Path) -> Result<(), String> {
    let text = render(emit.format, report, base)?;

    if let Some(parent) = emit.path.parent().filter(|p| !p.as_os_str().is_empty()) {
        std::fs::create_dir_all(parent)
            .map_err(|err| format!("could not create {}: {err}", parent.display()))?;
    }

    std::fs::write(&emit.path, text)
        .map_err(|err| format!("could not write {}: {err}", emit.path.display()))
}

fn render(format: Format, report: &Report, base: &Path) -> Result<String, String> {
    match format {
        Format::Json => wheeltap_report::json::render(report)
            .map_err(|err| format!("could not serialise the report: {err}")),
        Format::Markdown => Ok(wheeltap_report::markdown::render(report)),
        Format::Github => Ok(wheeltap_report::github::render(report, base)),
        Format::Sarif => {
            let rules: Vec<_> = wheeltap_rules::all()
                .iter()
                .map(|detector| detector.metadata())
                .collect();
            wheeltap_report::sarif::render(report, &rules, base)
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
        for format in wheeltap_report::ALL_FORMATS {
            let text = render(format, &report, Path::new("."))
                .unwrap_or_else(|err| panic!("{format} failed: {err}"));
            assert!(!text.is_empty(), "{format} produced nothing");
        }
    }

    #[test]
    fn emit_parses_a_format_and_a_path() {
        let emit: Emit = "sarif=out/report.sarif".parse().expect("valid");
        assert_eq!(emit.format, Format::Sarif);
        assert_eq!(emit.path, Path::new("out/report.sarif"));
    }

    /// These are typed into a workflow file, where the feedback loop on a typo
    /// is a push and a wait. The error has to say what was wrong.
    #[test]
    fn a_malformed_emit_is_rejected_with_a_useful_message() {
        assert!(
            "sarif".parse::<Emit>().unwrap_err().contains("FORMAT=PATH"),
            "a missing `=` names the shape expected"
        );
        assert!(
            "yaml=out.yml"
                .parse::<Emit>()
                .unwrap_err()
                .contains("sarif"),
            "an unknown format lists the ones that exist"
        );
        assert!("sarif=".parse::<Emit>().is_err(), "an empty path is a typo");
    }

    /// Windows path separators would otherwise be read as an absolute path on
    /// a drive; `=` splits once, from the left, so `C:\x` survives intact.
    #[test]
    fn an_emit_path_may_contain_equals_and_colons() {
        let emit: Emit = "json=out=1/a:b.json".parse().expect("valid");
        assert_eq!(emit.path, Path::new("out=1/a:b.json"));
    }

    #[test]
    fn the_annotation_base_mirrors_how_the_loader_roots_a_scan() {
        let dir = tempfile::tempdir().expect("tempdir");
        let file = dir.path().join("lib.rs");
        std::fs::write(&file, "fn main() {}").expect("write");

        assert_eq!(annotation_base(dir.path()), dir.path());
        assert_eq!(annotation_base(&file), dir.path());
    }

    #[test]
    fn emit_writes_every_requested_format_to_disk() {
        let dir = tempfile::tempdir().expect("tempdir");
        let report = report_with(&[Severity::Critical]);

        for format in wheeltap_report::ALL_FORMATS {
            // A nested path proves the parent directory is created rather than
            // failing the run at the last step of a long CI job.
            let path = dir.path().join("reports").join(format.to_string());
            let emit = Emit {
                format,
                path: path.clone(),
            };

            write_emit(&emit, &report, Path::new(".")).expect("write");
            let written = std::fs::read_to_string(&path).expect("read back");
            assert_eq!(
                written,
                render(format, &report, Path::new(".")).expect("render"),
                "{format} on disk differs from {format} on stdout"
            );
        }
    }
}
