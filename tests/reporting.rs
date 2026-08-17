//! Reporting, suppression, and baselines — the Phase 4 contract.
//!
//! The SARIF test is the load-bearing one. SARIF is what GitHub code scanning
//! consumes, and an output that *looks* right but fails validation is rejected
//! at upload with a message about the schema rather than about the mistake. So
//! it is validated against the official schema, vendored in `schemas/`, as part
//! of `cargo test` rather than only in CI.

use std::path::{Path, PathBuf};

use wheeltap_core::ProgramContext;
use wheeltap_core::baseline::Baseline;
use wheeltap_core::engine::{self, Report};
use wheeltap_core::finding::Severity;
use wheeltap_core::suppress::{Config, Suppressor};

fn root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
}

fn fixtures(kind: &str) -> PathBuf {
    root().join("fixtures").join(kind)
}

fn scan(path: &Path) -> Report {
    engine::run(&ProgramContext::scan(path), &wheeltap_rules::all())
}

fn rules() -> Vec<wheeltap_core::RuleMetadata> {
    wheeltap_rules::all()
        .iter()
        .map(|detector| detector.metadata())
        .collect()
}

// ---------------------------------------------------------------- SARIF ----

/// The Phase 4 exit criterion: valid SARIF 2.1.0.
#[test]
fn sarif_output_validates_against_the_official_schema() {
    let schema_text =
        std::fs::read_to_string(root().join("schemas/sarif-2.1.0.json")).expect("vendored schema");
    let schema: serde_json::Value = serde_json::from_str(&schema_text).expect("schema is JSON");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");

    let report = scan(&fixtures("vulnerable"));
    assert!(
        !report.findings.is_empty(),
        "need findings to be worth validating"
    );

    let text = wheeltap_report::sarif::render(&report, &rules()).expect("render");
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    let errors: Vec<String> = validator
        .iter_errors(&value)
        .map(|e| e.to_string())
        .collect();
    assert!(
        errors.is_empty(),
        "SARIF failed schema validation:\n{}",
        errors.join("\n")
    );
}

#[test]
fn sarif_is_valid_when_there_is_nothing_to_report() {
    let schema_text =
        std::fs::read_to_string(root().join("schemas/sarif-2.1.0.json")).expect("vendored schema");
    let schema: serde_json::Value = serde_json::from_str(&schema_text).expect("schema is JSON");
    let validator = jsonschema::validator_for(&schema).expect("schema compiles");

    let text = wheeltap_report::sarif::render(&Report::default(), &rules()).expect("render");
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    assert!(
        validator.is_valid(&value),
        "an empty run must still validate"
    );
}

/// The property GitHub relies on to match an alert across pushes.
#[test]
fn sarif_fingerprints_are_the_finding_identities() {
    let report = scan(&fixtures("vulnerable"));
    let text = wheeltap_report::sarif::render(&report, &rules()).expect("render");
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON");

    let results = value["runs"][0]["results"].as_array().expect("results");
    assert_eq!(results.len(), report.findings.len());

    for (result, finding) in results.iter().zip(&report.findings) {
        assert_eq!(
            result["partialFingerprints"]["wheeltapFindingId/v1"]
                .as_str()
                .expect("fingerprint"),
            finding.id.as_str()
        );
    }
}

// ------------------------------------------------------------ Markdown ----

#[test]
fn markdown_reports_every_finding_with_its_fix() {
    let report = scan(&fixtures("vulnerable"));
    let markdown = wheeltap_report::markdown::render(&report);

    for finding in &report.findings {
        assert!(
            markdown.contains(&format!(
                "`{}` {}:{}",
                finding.rule, finding.file, finding.line
            )),
            "{} at {}:{} is missing from the Markdown",
            finding.rule,
            finding.file,
            finding.line
        );
    }
    assert!(markdown.contains("**Fix.**"));
}

// --------------------------------------------------------- Suppression ----

/// Build a scan of one source string, with an optional config.
fn scan_source(source: &str, config: Config) -> Report {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("lib.rs"), source).expect("write");

    let ctx = ProgramContext::scan(dir.path());
    let mut report = engine::run(&ctx, &wheeltap_rules::all());
    let (kept, warnings) =
        Suppressor::new(config, &ctx.sources).apply(std::mem::take(&mut report.findings));
    report.findings = kept;
    report.diagnostics.extend(warnings);
    report
}

/// The vulnerable WT001 shape, which every suppression test starts from.
const UNSIGNED_AUTHORITY: &str = r#"
#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    /// CHECK: recorded on the vault
    pub authority: AccountInfo<'info>,
}
#[account]
pub struct Vault { pub authority: Pubkey, pub balance: u64 }
"#;

#[test]
fn without_suppression_the_finding_is_reported() {
    let report = scan_source(UNSIGNED_AUTHORITY, Config::default());
    assert_eq!(report.findings.len(), 1);
    assert_eq!(report.findings[0].rule, "WT001");
}

#[test]
fn an_inline_allow_directly_above_the_field_suppresses_it() {
    let source = UNSIGNED_AUTHORITY.replace(
        "    /// CHECK: recorded on the vault\n",
        "    /// CHECK: recorded on the vault\n    // wheeltap:allow(WT001) -- signs in the CPI callee\n",
    );
    let report = scan_source(&source, Config::default());

    assert!(report.findings.is_empty(), "{:?}", report.findings);
    assert!(
        report.diagnostics.is_empty(),
        "a justified suppression warns about nothing"
    );
}

/// The comment has to reach past the attribute, because that is where a reader
/// naturally puts it.
#[test]
fn an_inline_allow_reaches_over_attributes_and_doc_comments() {
    let source = UNSIGNED_AUTHORITY.replace(
        "    /// CHECK: recorded on the vault\n",
        "    // wheeltap:allow(WT001) -- reviewed 2026-08-12\n    /// CHECK: recorded on the vault\n    #[account(mut)]\n",
    );
    assert!(scan_source(&source, Config::default()).findings.is_empty());
}

#[test]
fn an_unjustified_suppression_is_honoured_but_warned_about() {
    let source = UNSIGNED_AUTHORITY.replace(
        "    /// CHECK: recorded on the vault\n",
        "    // wheeltap:allow(WT001)\n    /// CHECK: recorded on the vault\n",
    );
    let report = scan_source(&source, Config::default());

    assert!(report.findings.is_empty(), "still suppressed");
    assert_eq!(report.diagnostics.len(), 1, "but not silently");
    assert!(report.diagnostics[0].message.contains("justification"));
}

#[test]
fn an_allow_for_a_different_rule_does_not_suppress() {
    let source = UNSIGNED_AUTHORITY.replace(
        "    /// CHECK: recorded on the vault\n",
        "    // wheeltap:allow(WT009) -- unrelated\n    /// CHECK: recorded on the vault\n",
    );
    assert_eq!(scan_source(&source, Config::default()).findings.len(), 1);
}

/// A suppression must not leak onto a neighbouring field.
#[test]
fn an_allow_does_not_reach_past_unrelated_code() {
    let source = r#"
#[derive(Accounts)]
pub struct Withdraw<'info> {
    // wheeltap:allow(WT001) -- meant for the vault, not the authority
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    pub authority: AccountInfo<'info>,
}
#[account]
pub struct Vault { pub authority: Pubkey, pub balance: u64 }
"#;
    assert_eq!(
        scan_source(source, Config::default()).findings.len(),
        1,
        "the allow sits above `vault`, and `pub vault` breaks the run above `authority`"
    );
}

#[test]
fn a_config_can_switch_off_a_whole_rule() {
    let config = Config::parse("[suppress]\nrules = [\"WT001\"]").expect("config");
    assert!(scan_source(UNSIGNED_AUTHORITY, config).findings.is_empty());
}

#[test]
fn a_config_can_downgrade_a_rules_severity() {
    let config = Config::parse("[severity]\nWT001 = \"low\"").expect("config");
    let report = scan_source(UNSIGNED_AUTHORITY, config);

    assert_eq!(report.findings.len(), 1, "still reported");
    assert_eq!(report.findings[0].severity, Severity::Low, "but downgraded");
}

#[test]
fn path_suppression_uses_globs() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::create_dir_all(dir.path().join("legacy")).expect("mkdir");
    std::fs::write(dir.path().join("legacy/lib.rs"), UNSIGNED_AUTHORITY).expect("write");
    std::fs::write(dir.path().join("current.rs"), UNSIGNED_AUTHORITY).expect("write");

    let ctx = ProgramContext::scan(dir.path());
    let mut report = engine::run(&ctx, &wheeltap_rules::all());
    assert_eq!(report.findings.len(), 2, "both files are vulnerable");

    let config = Config::parse("[suppress]\npaths = [\"legacy/**\"]").expect("config");
    let (kept, _) =
        Suppressor::new(config, &ctx.sources).apply(std::mem::take(&mut report.findings));

    assert_eq!(kept.len(), 1);
    assert_eq!(kept[0].file, "current.rs");
}

// ------------------------------------------------------------ Baseline ----

#[test]
fn a_baseline_of_the_same_scan_leaves_nothing_new() {
    let report = scan(&fixtures("vulnerable"));
    let json = wheeltap_report::json::render(&report).expect("render");

    let baseline = Baseline::parse(&json).expect("parse");
    assert_eq!(baseline.len(), report.findings.len());
    assert!(
        baseline.filter_new(report.findings).is_empty(),
        "unchanged code produces no new findings"
    );
}

/// The property the whole identity scheme exists for: code that moves is not
/// new code.
#[test]
fn a_finding_that_moved_is_not_reported_as_new() {
    let original =
        std::fs::read_to_string(fixtures("vulnerable").join("WT001_missing_signer/vault.rs"))
            .expect("read fixture");

    let baseline_report = scan(&fixtures("vulnerable").join("WT001_missing_signer"));
    let baseline =
        Baseline::parse(&wheeltap_report::json::render(&baseline_report).expect("render"))
            .expect("parse");

    // Push everything down the file and reformat around it.
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(
        dir.path().join("vault.rs"),
        format!("// a new header\n//\n// three lines of it\n\n{original}"),
    )
    .expect("write");

    let moved = scan(dir.path());
    assert!(!moved.findings.is_empty(), "still vulnerable");
    assert!(
        moved
            .findings
            .iter()
            .any(|f| f.line != baseline_report.findings[0].line),
        "the code really did move"
    );
    assert!(
        baseline.filter_new(moved.findings).is_empty(),
        "moving code must not resurface as new findings"
    );
}

#[test]
fn a_new_vulnerability_appears_against_a_baseline() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("lib.rs"), UNSIGNED_AUTHORITY).expect("write");
    let first = scan(dir.path());
    let baseline =
        Baseline::parse(&wheeltap_report::json::render(&first).expect("render")).expect("parse");

    // Add a second, different vulnerability.
    std::fs::write(
        dir.path().join("second.rs"),
        r#"
#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut, has_one = beneficiary)]
    pub grant: Account<'info, Grant>,
    pub beneficiary: Signer<'info>,
    /// CHECK: the clock sysvar
    pub clock: AccountInfo<'info>,
}
#[account]
pub struct Grant { pub beneficiary: Pubkey }
"#,
    )
    .expect("write");

    let new = baseline.filter_new(scan(dir.path()).findings);
    assert_eq!(new.len(), 1, "{new:?}");
    assert_eq!(new[0].rule, "WT009");
}

#[test]
fn fixing_a_finding_removes_it_without_the_baseline_resurrecting_it() {
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("lib.rs"), UNSIGNED_AUTHORITY).expect("write");
    let baseline =
        Baseline::parse(&wheeltap_report::json::render(&scan(dir.path())).expect("render"))
            .expect("parse");

    std::fs::write(
        dir.path().join("lib.rs"),
        UNSIGNED_AUTHORITY.replace(
            "pub authority: AccountInfo<'info>",
            "pub authority: Signer<'info>",
        ),
    )
    .expect("write");

    let after = scan(dir.path());
    assert!(after.findings.is_empty(), "the fix cleared it");
    assert!(baseline.filter_new(after.findings).is_empty());
}

// ------------------------------------------------- GitHub annotations ----

/// Parse one workflow command back into its parts.
///
/// Deliberately a real parse rather than a substring search: if the escaping
/// is wrong, a comma in a message invents a property and this notices, where
/// `contains("file=")` would not.
fn parse_command(line: &str) -> (String, std::collections::HashMap<String, String>, String) {
    let rest = line.strip_prefix("::").expect("commands start with ::");
    let (head, body) = rest.split_once("::").expect("a command has a body");
    let (level, properties) = head.split_once(' ').expect("a command has properties");

    let properties = properties
        .split(',')
        .map(|pair| {
            let (key, value) = pair.split_once('=').unwrap_or_else(|| {
                panic!("`{pair}` is not a key=value pair — escaping probably leaked a comma")
            });
            (key.to_string(), value.to_string())
        })
        .collect();

    (level.to_string(), properties, body.to_string())
}

/// The Phase 5 test that cannot be written as a workflow assertion: every
/// annotation must name a path that exists from the repository root, at a line
/// that exists in it, holding the code the finding is about.
///
/// A wrong path here does not fail — GitHub just quietly declines to put the
/// annotation on the diff, and the feature appears to work while doing nothing.
#[test]
fn every_annotation_lands_on_the_line_it_describes() {
    let base = Path::new("fixtures/vulnerable");
    let report = scan(&fixtures("vulnerable"));
    assert!(!report.findings.is_empty(), "need findings to place");

    let rendered = wheeltap_report::github::render(&report, base);
    let lines: Vec<&str> = rendered.lines().collect();
    assert_eq!(
        lines.len(),
        report.findings.len() + report.diagnostics.len(),
        "one command per line, and no command split across lines"
    );

    for (line, finding) in lines.iter().zip(&report.findings) {
        let (level, properties, body) = parse_command(line);
        assert!(
            ["error", "warning", "notice"].contains(&level.as_str()),
            "{level} is not a level GitHub knows"
        );

        // The path is repository-relative, so it resolves from the repo root.
        let path = root().join(properties.get("file").expect("file property"));
        let source = std::fs::read_to_string(&path)
            .unwrap_or_else(|err| panic!("annotation names {}: {err}", path.display()));

        let number: usize = properties["line"].parse().expect("line is a number");
        let text = source
            .lines()
            .nth(number - 1)
            .unwrap_or_else(|| panic!("{} has no line {number}", path.display()));

        assert_eq!(
            text.trim(),
            finding.snippet.trim(),
            "the annotation on {}:{number} points at the wrong line",
            path.display()
        );
        assert!(!body.is_empty(), "an annotation with no message is useless");
    }
}

/// Rust is full of commas and colons, and an unescaped one either truncates
/// the command or fabricates a property. Proven against real findings rather
/// than a hand-written string.
#[test]
fn annotations_survive_the_punctuation_in_real_findings() {
    let report = scan(&fixtures("vulnerable"));
    let rendered = wheeltap_report::github::render(&report, Path::new("fixtures/vulnerable"));

    let expected = ["file", "line", "col", "title"];
    for line in rendered.lines() {
        let (_, properties, _) = parse_command(line);
        for key in expected {
            assert!(properties.contains_key(key), "`{key}` missing from {line}");
        }
        for key in properties.keys() {
            assert!(
                expected.contains(&key.as_str()) || key == "endLine",
                "`{key}` is not a property we emit — escaping leaked a comma: {line}"
            );
        }
    }
}

/// The severity a finding was given has to survive the squeeze into GitHub's
/// three levels, or every critical and high finding looks identical.
#[test]
fn the_severity_of_every_annotation_is_recoverable() {
    let report = scan(&fixtures("vulnerable"));
    let rendered = wheeltap_report::github::render(&report, Path::new("fixtures/vulnerable"));

    for (line, finding) in rendered.lines().zip(&report.findings) {
        let (_, properties, _) = parse_command(line);
        assert_eq!(
            properties["title"],
            format!("{} {}", finding.rule, finding.severity),
            "the title has to carry the rule and the real severity"
        );
    }
}

/// Safe fixtures produce no annotations at all — not an empty command, not a
/// blank line. A clean run must be genuinely silent.
#[test]
fn a_clean_scan_annotates_nothing() {
    let rendered =
        wheeltap_report::github::render(&scan(&fixtures("safe")), Path::new("fixtures/safe"));
    assert_eq!(rendered, "", "safe fixtures annotated: {rendered}");
}
