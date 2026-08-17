//! SARIF 2.1.0 output.
//!
//! SARIF is what unlocks GitHub code scanning: upload it and findings appear as
//! inline annotations on the pull request that introduced them. That is the
//! whole distribution story for this tool, so the output is validated against
//! the official schema in `tests/reporting.rs` rather than eyeballed.
//!
//! # Fingerprints
//!
//! `partialFingerprints` is where Wheeltap's deterministic finding identity
//! earns its place a second time. GitHub uses it to decide whether a result in
//! this run is the *same* result as one in the last run. Without it, code
//! scanning matches on file and line, so moving a function reopens every alert
//! beneath it and closes the originals — the same noise `--baseline` exists to
//! prevent, in someone else's UI.

use std::path::Path;

use serde::Serialize;

use crate::path::repo_relative;
use wheeltap_core::engine::Report;
use wheeltap_core::finding::{Finding, Severity};

/// The SARIF version this output conforms to.
pub const SARIF_VERSION: &str = "2.1.0";
const SCHEMA_URL: &str = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json";

#[derive(Debug, Serialize)]
pub struct Sarif {
    #[serde(rename = "$schema")]
    pub schema: &'static str,
    pub version: &'static str,
    pub runs: Vec<Run>,
}

#[derive(Debug, Serialize)]
pub struct Run {
    pub tool: Tool,
    pub results: Vec<SarifResult>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub invocations: Vec<Invocation>,
}

#[derive(Debug, Serialize)]
pub struct Tool {
    pub driver: Driver,
}

#[derive(Debug, Serialize)]
pub struct Driver {
    pub name: &'static str,
    pub version: &'static str,
    #[serde(rename = "informationUri")]
    pub information_uri: &'static str,
    pub rules: Vec<ReportingDescriptor>,
}

#[derive(Debug, Serialize)]
pub struct ReportingDescriptor {
    pub id: String,
    pub name: String,
    #[serde(rename = "shortDescription")]
    pub short_description: Message,
    #[serde(rename = "fullDescription")]
    pub full_description: Message,
    pub help: Message,
    #[serde(rename = "helpUri", skip_serializing_if = "Option::is_none")]
    pub help_uri: Option<String>,
    #[serde(rename = "defaultConfiguration")]
    pub default_configuration: ReportingConfiguration,
    pub properties: RuleProperties,
}

#[derive(Debug, Serialize)]
pub struct RuleProperties {
    /// GitHub renders these as the alert's tags.
    pub tags: Vec<String>,
    /// GitHub's security-severity is a number, and drives alert ranking.
    #[serde(rename = "security-severity")]
    pub security_severity: String,
}

#[derive(Debug, Serialize)]
pub struct ReportingConfiguration {
    pub level: &'static str,
}

#[derive(Debug, Serialize)]
pub struct SarifResult {
    #[serde(rename = "ruleId")]
    pub rule_id: String,
    #[serde(rename = "ruleIndex")]
    pub rule_index: usize,
    pub level: &'static str,
    pub message: Message,
    pub locations: Vec<Location>,
    #[serde(rename = "partialFingerprints")]
    pub partial_fingerprints: Fingerprints,
    pub properties: ResultProperties,
}

#[derive(Debug, Serialize)]
pub struct Fingerprints {
    /// Versioned, so that changing the identity scheme later does not silently
    /// reopen every alert — it becomes a new fingerprint key instead.
    #[serde(rename = "wheeltapFindingId/v1")]
    pub finding_id: String,
}

#[derive(Debug, Serialize)]
pub struct ResultProperties {
    pub confidence: String,
    #[serde(rename = "itemPath")]
    pub item_path: String,
}

#[derive(Debug, Serialize)]
pub struct Message {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct Location {
    #[serde(rename = "physicalLocation")]
    pub physical_location: PhysicalLocation,
}

#[derive(Debug, Serialize)]
pub struct PhysicalLocation {
    #[serde(rename = "artifactLocation")]
    pub artifact_location: ArtifactLocation,
    pub region: Region,
}

#[derive(Debug, Serialize)]
pub struct ArtifactLocation {
    pub uri: String,
}

#[derive(Debug, Serialize)]
pub struct Region {
    #[serde(rename = "startLine")]
    pub start_line: usize,
    #[serde(rename = "startColumn")]
    pub start_column: usize,
    #[serde(rename = "endLine")]
    pub end_line: usize,
    pub snippet: ArtifactContent,
}

#[derive(Debug, Serialize)]
pub struct ArtifactContent {
    pub text: String,
}

#[derive(Debug, Serialize)]
pub struct Invocation {
    #[serde(rename = "executionSuccessful")]
    pub execution_successful: bool,
    #[serde(rename = "toolExecutionNotifications")]
    pub tool_execution_notifications: Vec<Notification>,
}

#[derive(Debug, Serialize)]
pub struct Notification {
    pub level: &'static str,
    pub message: Message,
}

/// Build the SARIF view of a report.
///
/// `rules` is the metadata for every rule that *could* have fired, not only
/// those that did: SARIF consumers use the driver's rule list to render help
/// text, and a rule missing from it degrades the alert.
///
/// `base` is the scanned path relative to the repository root. GitHub resolves
/// `artifactLocation.uri` from the repository root, and an alert whose uri does
/// not resolve there is ingested and displayed with no source behind it — the
/// upload succeeds and the alert is useless. Pass `Path::new(".")` when the
/// scan ran at the repository root.
#[must_use]
pub fn build(report: &Report, rules: &[wheeltap_core::RuleMetadata], base: &Path) -> Sarif {
    let descriptors: Vec<ReportingDescriptor> = rules.iter().map(describe).collect();

    let results = report
        .findings
        .iter()
        .map(|finding| {
            let rule_index = rules
                .iter()
                .position(|rule| rule.id == finding.rule)
                .unwrap_or(0);
            result(finding, rule_index, base)
        })
        .collect();

    // Parse failures are coverage gaps. SARIF has a place for them, and putting
    // them there means a clean-looking run still shows what it could not read.
    let notifications: Vec<Notification> = report
        .diagnostics
        .iter()
        .map(|diagnostic| Notification {
            level: "warning",
            message: Message {
                text: diagnostic.to_string(),
            },
        })
        .collect();

    Sarif {
        schema: SCHEMA_URL,
        version: SARIF_VERSION,
        runs: vec![Run {
            tool: Tool {
                driver: Driver {
                    name: "wheeltap",
                    version: env!("CARGO_PKG_VERSION"),
                    information_uri: "https://github.com/JoshBlazer/wheeltap",
                    rules: descriptors,
                },
            },
            results,
            invocations: vec![Invocation {
                execution_successful: true,
                tool_execution_notifications: notifications,
            }],
        }],
    }
}

fn describe(rule: &wheeltap_core::RuleMetadata) -> ReportingDescriptor {
    ReportingDescriptor {
        id: rule.id.to_string(),
        name: rule.name.to_string(),
        short_description: Message {
            text: rule.description.to_string(),
        },
        full_description: Message {
            text: rule.description.to_string(),
        },
        help: Message {
            text: rule.remediation.to_string(),
        },
        help_uri: rule.references.first().map(|url| (*url).to_string()),
        default_configuration: ReportingConfiguration {
            level: level(rule.severity),
        },
        properties: RuleProperties {
            tags: vec!["security".into(), "solana".into(), "anchor".into()],
            security_severity: security_severity(rule.severity).to_string(),
        },
    }
}

fn result(finding: &Finding, rule_index: usize, base: &Path) -> SarifResult {
    SarifResult {
        rule_id: finding.rule.to_string(),
        rule_index,
        level: level(finding.severity),
        message: Message {
            text: finding.message.clone(),
        },
        locations: vec![Location {
            physical_location: PhysicalLocation {
                artifact_location: ArtifactLocation {
                    uri: repo_relative(base, &finding.file),
                },
                region: Region {
                    start_line: finding.line,
                    start_column: finding.column,
                    end_line: finding.location.end.line.max(finding.line),
                    snippet: ArtifactContent {
                        text: finding.snippet.clone(),
                    },
                },
            },
        }],
        partial_fingerprints: Fingerprints {
            finding_id: finding.id.to_string(),
        },
        properties: ResultProperties {
            confidence: finding.confidence.to_string(),
            item_path: finding.item_path.clone(),
        },
    }
}

/// Map severity onto SARIF's four levels.
///
/// SARIF has no "critical", so Critical and High both become `error`. The
/// distinction is not lost: it survives in `security-severity`, which is what
/// GitHub ranks alerts by.
fn level(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical | Severity::High => "error",
        Severity::Medium | Severity::Low => "warning",
        Severity::Info => "note",
    }
}

/// GitHub's numeric severity, on the CVSS-like 0-10 scale it expects.
fn security_severity(severity: Severity) -> &'static str {
    match severity {
        Severity::Critical => "9.0",
        Severity::High => "7.0",
        Severity::Medium => "5.0",
        Severity::Low => "3.0",
        Severity::Info => "1.0",
    }
}

/// Render a report as SARIF JSON.
///
/// # Errors
///
/// Propagates a `serde_json` failure.
pub fn render(
    report: &Report,
    rules: &[wheeltap_core::RuleMetadata],
    base: &Path,
) -> Result<String, serde_json::Error> {
    let mut text = serde_json::to_string_pretty(&build(report, rules, base))?;
    text.push('\n');
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests_support::{report_with, sample_rules};

    #[test]
    fn severity_maps_onto_sarif_levels() {
        assert_eq!(level(Severity::Critical), "error");
        assert_eq!(level(Severity::High), "error");
        assert_eq!(level(Severity::Medium), "warning");
        assert_eq!(level(Severity::Info), "note");
    }

    #[test]
    fn the_report_carries_the_finding_identity_as_a_fingerprint() {
        let report = report_with(&[Severity::Critical]);
        let sarif = build(&report, &sample_rules(), Path::new("."));
        let result = &sarif.runs[0].results[0];

        assert_eq!(
            result.partial_fingerprints.finding_id,
            report.findings[0].id.to_string(),
            "GitHub matches alerts across runs by this"
        );
    }

    #[test]
    fn results_index_into_the_rule_list() {
        let report = report_with(&[Severity::Critical]);
        let rules = sample_rules();
        let sarif = build(&report, &rules, Path::new("."));

        let result = &sarif.runs[0].results[0];
        assert_eq!(rules[result.rule_index].id, result.rule_id);
    }

    #[test]
    fn every_rule_is_described_whether_or_not_it_fired() {
        let sarif = build(&Report::default(), &sample_rules(), Path::new("."));
        assert_eq!(sarif.runs[0].tool.driver.rules.len(), sample_rules().len());
        assert!(sarif.runs[0].results.is_empty());
    }

    #[test]
    fn diagnostics_become_tool_notifications() {
        let mut report = report_with(&[Severity::High]);
        report
            .diagnostics
            .push(wheeltap_core::diag::Diagnostic::warning(
                "a.rs",
                "unparseable",
            ));

        let sarif = build(&report, &sample_rules(), Path::new("."));
        let notifications = &sarif.runs[0].invocations[0].tool_execution_notifications;
        assert_eq!(notifications.len(), 1);
        assert!(notifications[0].message.text.contains("unparseable"));
    }

    #[test]
    fn output_is_stable_across_runs() {
        let rules = sample_rules();
        assert_eq!(
            render(&report_with(&[Severity::High]), &rules, Path::new(".")).expect("render"),
            render(&report_with(&[Severity::High]), &rules, Path::new(".")).expect("render")
        );
    }
}
