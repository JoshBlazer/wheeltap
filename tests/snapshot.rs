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
