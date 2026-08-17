//! Snapshot of the program model.
//!
//! The snapshot is the readable record of what Wheeltap understands. A diff
//! here means the model changed; review it and either accept the improvement or
//! fix the regression. `cargo insta review` walks the changes.
//!
//! Only `escrow` is snapshotted. It is small enough to read in a diff, which is
//! the entire value — a snapshot of drift's 155 account structs would be
//! rubber-stamped every time it changed.

use std::path::Path;

use wheeltap_core::ProgramContext;

#[test]
fn escrow_context_model() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/corpus/escrow");
    let summary = ProgramContext::scan(&path).summary();

    insta::assert_json_snapshot!("escrow_context", summary);
}

/// The full JSON report for the vulnerable corpus.
///
/// This is the output a consumer parses and `--baseline` reads back, so its
/// exact shape is the contract. A diff here means the report changed; the
/// finding identities in it should change only when the fixtures do.
#[test]
fn vulnerable_corpus_json_report() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/vulnerable");
    let report = wheeltap_core::engine::run(&ProgramContext::scan(&path), &wheeltap_rules::all());

    let json: serde_json::Value =
        serde_json::from_str(&wheeltap_report::json::render(&report).expect("render"))
            .expect("valid JSON");

    insta::assert_json_snapshot!("vulnerable_report", json);
}

/// Markdown output for the vulnerable corpus.
///
/// This is what a reviewer reads in a CI log, so a diff here is a change to the
/// thing people actually look at.
#[test]
fn vulnerable_corpus_markdown_report() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/vulnerable");
    let report = wheeltap_core::engine::run(&ProgramContext::scan(&path), &wheeltap_rules::all());

    insta::assert_snapshot!(
        "vulnerable_markdown",
        wheeltap_report::markdown::render(&report)
    );
}

/// SARIF output for the vulnerable corpus.
///
/// Snapshotted as well as schema-validated: the schema says the shape is legal,
/// and this says the content did not change by accident.
#[test]
fn vulnerable_corpus_sarif_report() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/vulnerable");
    let report = wheeltap_core::engine::run(&ProgramContext::scan(&path), &wheeltap_rules::all());
    let rules: Vec<_> = wheeltap_rules::all()
        .iter()
        .map(|detector| detector.metadata())
        .collect();

    let json: serde_json::Value = serde_json::from_str(
        &wheeltap_report::sarif::render(&report, &rules, Path::new("fixtures/vulnerable"))
            .expect("render"),
    )
    .expect("valid JSON");

    insta::assert_json_snapshot!("vulnerable_sarif", json);
}

/// GitHub Actions annotations for the vulnerable corpus.
///
/// This is the text a pull-request reviewer sees as inline bubbles. It is also
/// the format most easily broken by accident — a stray comma in a message
/// silently changes what GitHub parses — so the exact bytes are pinned.
#[test]
fn vulnerable_corpus_github_annotations() {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("fixtures/vulnerable");
    let report = wheeltap_core::engine::run(&ProgramContext::scan(&path), &wheeltap_rules::all());

    insta::assert_snapshot!(
        "vulnerable_github",
        wheeltap_report::github::render(&report, Path::new("fixtures/vulnerable"))
    );
}
