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
