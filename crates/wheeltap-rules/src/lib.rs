//! Detector implementations, one module per rule.
//!
//! Every rule here ships with vulnerable fixtures it must catch and safe
//! fixtures it must not flag, written *before* the implementation. The corpus is
//! the specification; see `fixtures/README.md`.

mod body;
mod names;

mod wt001_missing_signer;
mod wt002_missing_owner;
mod wt003_unchecked_arithmetic;

use wheeltap_core::Detector;

pub use wt001_missing_signer::MissingSigner;
pub use wt002_missing_owner::MissingOwner;
pub use wt003_unchecked_arithmetic::UncheckedArithmetic;

/// Rule identifiers the catalogue plans to cover, in build order.
///
/// A rule listed here is not necessarily implemented; [`all`] is the truth
/// about what runs, and `PROGRESS.md` tracks status.
pub const PLANNED_RULES: &[&str] = &[
    "WT001", "WT002", "WT003", "WT004", "WT005", "WT006", "WT007", "WT008", "WT009", "WT010",
    "WT011", "WT012",
];

/// Every implemented detector.
#[must_use]
pub fn all() -> Vec<Box<dyn Detector>> {
    vec![
        Box::new(MissingSigner),
        Box::new(MissingOwner),
        Box::new(UncheckedArithmetic),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;

    #[test]
    fn planned_rule_ids_are_unique_and_well_formed() {
        let mut seen = BTreeSet::new();
        for rule in PLANNED_RULES {
            assert!(seen.insert(*rule), "duplicate rule id {rule}");
            assert!(rule.starts_with("WT"), "rule id {rule} is not WT-prefixed");
            assert_eq!(rule.len(), 5, "rule id {rule} is not WTnnn");
        }
    }

    #[test]
    fn every_registered_detector_is_planned_and_self_consistent() {
        let mut seen = BTreeSet::new();
        for detector in all() {
            let id = detector.rule_id();
            assert!(seen.insert(id), "{id} is registered twice");
            assert!(PLANNED_RULES.contains(&id), "{id} is not in the catalogue");
            assert_eq!(
                detector.metadata().id,
                id,
                "{id} reports a different id in its metadata"
            );
            assert!(!detector.metadata().remediation.is_empty());
            assert!(!detector.metadata().references.is_empty());
        }
    }

    #[test]
    fn registered_detectors_match_the_documented_phase_two_set() {
        let ids: Vec<_> = all().iter().map(|d| d.rule_id()).collect();
        assert_eq!(ids, ["WT001", "WT002", "WT003"]);
    }
}
