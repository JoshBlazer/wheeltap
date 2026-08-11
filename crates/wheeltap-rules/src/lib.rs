//! Detector implementations, one module per rule.
//!
//! Rules land in Phase 2 (WT001-WT003) and Phase 3 (WT004-WT012). Each ships
//! with its vulnerable and safe fixtures before its implementation, per the
//! build spec's fixture-first rule.

/// Rule identifiers this crate intends to implement, in build order.
///
/// Present from Phase 0 so the CLI and documentation have a single source of
/// truth for the catalogue; a rule appearing here does not mean it is
/// implemented. `PROGRESS.md` tracks implementation status.
pub const PLANNED_RULES: &[&str] = &[
    "WT001", "WT002", "WT003", "WT004", "WT005", "WT006", "WT007", "WT008", "WT009", "WT010",
    "WT011", "WT012",
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn planned_rule_ids_are_unique_and_well_formed() {
        let mut seen = std::collections::BTreeSet::new();
        for rule in PLANNED_RULES {
            assert!(seen.insert(*rule), "duplicate rule id {rule}");
            assert!(rule.starts_with("WT"), "rule id {rule} is not WT-prefixed");
            assert_eq!(rule.len(), 5, "rule id {rule} is not WTnnn");
        }
    }
}
