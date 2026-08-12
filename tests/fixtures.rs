//! The fixture corpus, which is the detectors' specification.
//!
//! Three gates, in ascending order of how much they matter:
//!
//! 1. **True positives** — every vulnerable fixture is flagged by the rule it
//!    is named for.
//! 2. **No false positives** — no safe fixture is flagged by *any* rule. This
//!    runs globally rather than per rule, because the failure mode it exists to
//!    catch is cross-detector: WT003 firing inside a fixture written to test
//!    WT001 is exactly the kind of noise that gets a tool switched off.
//! 3. **Known gaps** — documented misses stay missed, and say so loudly when
//!    they stop being missed.

use std::path::{Path, PathBuf};

use wheeltap_core::ProgramContext;
use wheeltap_core::engine::{self, Report};
use wheeltap_core::finding::Severity;

fn fixtures(kind: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures")
        .join(kind)
}

fn scan(path: &Path) -> Report {
    engine::run(&ProgramContext::scan(path), &wheeltap_rules::all())
}

/// Describe findings compactly enough to read in a test failure.
fn describe(report: &Report) -> Vec<String> {
    report
        .findings
        .iter()
        .map(|f| format!("{} {}:{} {}", f.rule, f.file, f.line, f.item_path))
        .collect()
}

/// Every vulnerable fixture directory, paired with the rule it exercises.
fn vulnerable_cases() -> Vec<(String, PathBuf)> {
    let mut cases: Vec<_> = std::fs::read_dir(fixtures("vulnerable"))
        .expect("vulnerable fixtures directory")
        .filter_map(|entry| {
            let path = entry.expect("readable entry").path();
            if !path.is_dir() {
                return None;
            }
            // Directories are named `WT001_missing_signer`; the rule is the prefix.
            let rule = path.file_name()?.to_str()?.split('_').next()?.to_string();
            Some((rule, path))
        })
        .collect();
    cases.sort();
    assert!(!cases.is_empty(), "no vulnerable fixtures found");
    cases
}

/// Gate 1: each vulnerable fixture is caught by its own rule.
#[test]
fn every_vulnerable_fixture_is_flagged_by_its_rule() {
    for (rule, path) in vulnerable_cases() {
        let report = scan(&path);
        assert!(
            report.findings.iter().any(|f| f.rule == rule),
            "{rule} did not flag its own fixture at {}. Findings: {:?}",
            path.display(),
            describe(&report)
        );
    }
}

/// Gate 2: the assertion that decides whether the tool is usable.
#[test]
fn no_safe_fixture_is_flagged_by_any_rule() {
    let report = scan(&fixtures("safe"));

    assert!(
        report.findings.is_empty(),
        "safe fixtures must never be flagged, by any rule. \
         Fix the detector -- never weaken the fixture. Findings: {:#?}",
        describe(&report)
    );
}

/// Every safe fixture is also checked on its own, so that a directory being
/// skipped entirely cannot masquerade as a clean result.
#[test]
fn safe_fixtures_are_actually_analysed() {
    let report = scan(&fixtures("safe"));

    assert!(report.files_scanned >= 6, "expected the whole safe corpus");
    assert!(report.lines_scanned > 300);
    assert!(
        report.diagnostics.is_empty(),
        "a safe fixture that failed to parse would pass gate 2 for the wrong reason: {:?}",
        report.diagnostics
    );
}

/// Gate 3: documented misses stay documented.
///
/// Failing here is good news that needs acting on — see
/// `fixtures/known_gaps/README.md`.
#[test]
fn known_gaps_are_still_missed() {
    let report = scan(&fixtures("known_gaps"));

    assert!(
        report.findings.is_empty(),
        "a known gap is now caught, which is an improvement: promote the fixture \
         from fixtures/known_gaps/ to fixtures/vulnerable/ and update the README \
         and PROGRESS.md. Findings: {:?}",
        describe(&report)
    );
}

/// The Phase 2 exit criterion, as the build spec states it.
#[test]
fn scanning_the_vulnerable_corpus_reports_all_three_rules() {
    let report = scan(&fixtures("vulnerable"));

    for rule in ["WT001", "WT002", "WT003"] {
        assert!(
            report.findings.iter().any(|f| f.rule == rule),
            "{rule} reported nothing across the whole vulnerable corpus"
        );
    }
    assert!(report.has_findings_at_or_above(Severity::Critical));
}

/// Findings must be reproducible run to run (build spec invariant 4).
#[test]
fn scanning_is_deterministic() {
    let first = scan(&fixtures("vulnerable"));
    let second = scan(&fixtures("vulnerable"));

    assert_eq!(describe(&first), describe(&second));
    assert_eq!(
        wheeltap_report::json::render(&first).expect("render"),
        wheeltap_report::json::render(&second).expect("render"),
    );
}

/// Identity must survive the code moving, and change when the code changes.
/// Asserted here on a real detector rather than a hand-built string, so the
/// property is tested end to end.
#[test]
fn finding_identity_survives_movement_but_not_change() {
    let original =
        std::fs::read_to_string(fixtures("vulnerable").join("WT001_missing_signer/vault.rs"))
            .expect("read fixture");

    let baseline = scan(&fixtures("vulnerable").join("WT001_missing_signer"));
    let baseline_id = baseline
        .findings
        .iter()
        .find(|f| f.rule == "WT001")
        .expect("WT001 finding")
        .id
        .clone();

    // Move the offending code down the file and reformat around it.
    let moved = format!("// a new comment\n// and another\n\n{original}");
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("vault.rs"), &moved).expect("write");
    let after_move = scan(dir.path());
    let moved_finding = after_move
        .findings
        .iter()
        .find(|f| f.rule == "WT001")
        .expect("still flagged after moving");

    assert_ne!(
        moved_finding.line, baseline.findings[0].line,
        "the fixture really did move"
    );
    assert_eq!(
        moved_finding.id, baseline_id,
        "identity must survive the code moving within its file"
    );

    // Now change the offending code itself.
    let fixed = original.replace(
        "pub authority: AccountInfo<'info>,",
        "pub authority: Signer<'info>,",
    );
    let dir = tempfile::TempDir::new().expect("tempdir");
    std::fs::write(dir.path().join("vault.rs"), fixed).expect("write");

    assert!(
        !scan(dir.path()).findings.iter().any(|f| f.rule == "WT001"),
        "fixing the code must clear the finding"
    );
}

/// A scan of correct real-world code should be quiet. This is the standing
/// false-positive budget, asserted rather than assumed.
#[test]
fn the_real_corpus_stays_quiet() {
    let corpus = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/corpus");

    let escrow = scan(&corpus.join("escrow"));
    assert!(
        escrow.findings.is_empty(),
        "escrow is small, idiomatic, correct Anchor and must stay clean: {:?}",
        describe(&escrow)
    );

    // Across 76,000 lines of third-party code the tool reports a handful of
    // findings, all hand-triaged in docs/BENCHMARKS.md. The budget is asserted
    // so that a change which floods the corpus fails here rather than in
    // someone's CI.
    let total: usize = ["anchor-misc", "drift"]
        .iter()
        .map(|name| scan(&corpus.join(name)).findings.len())
        .sum();
    assert!(
        total <= 10,
        "false-positive budget exceeded on the real corpus: {total} findings"
    );
}
