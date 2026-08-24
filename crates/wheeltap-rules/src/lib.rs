//! Detector implementations, one module per rule.
//!
//! Every rule here ships with vulnerable fixtures it must catch and safe
//! fixtures it must not flag, written *before* the implementation. The corpus is
//! the specification; see `fixtures/README.md`.

mod body;
mod links;
mod names;

mod wt001_missing_signer;
mod wt002_missing_owner;
mod wt003_unchecked_arithmetic;
mod wt004_reinitialisation;
mod wt005_missing_has_one;
mod wt006_non_canonical_bump;
mod wt007_arbitrary_cpi;
mod wt008_unsafe_close;
mod wt009_sysvar_spoofing;
mod wt010_unchecked_deserialisation;
mod wt011_duplicate_mutable;
mod wt012_alloc_in_loop;

use wheeltap_core::Detector;

pub use wt001_missing_signer::MissingSigner;
pub use wt002_missing_owner::MissingOwner;
pub use wt003_unchecked_arithmetic::UncheckedArithmetic;
pub use wt004_reinitialisation::Reinitialisation;
pub use wt005_missing_has_one::MissingHasOne;
pub use wt006_non_canonical_bump::NonCanonicalBump;
pub use wt007_arbitrary_cpi::ArbitraryCpi;
pub use wt008_unsafe_close::UnsafeClose;
pub use wt009_sysvar_spoofing::SysvarSpoofing;
pub use wt010_unchecked_deserialisation::UncheckedDeserialisation;
pub use wt011_duplicate_mutable::DuplicateMutable;
pub use wt012_alloc_in_loop::AllocInLoop;

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
        Box::new(Reinitialisation),
        Box::new(MissingHasOne),
        Box::new(NonCanonicalBump),
        Box::new(ArbitraryCpi),
        Box::new(UnsafeClose),
        Box::new(SysvarSpoofing),
        Box::new(UncheckedDeserialisation),
        Box::new(DuplicateMutable),
        Box::new(AllocInLoop),
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
    fn registered_detectors_are_in_catalogue_order() {
        let ids: Vec<_> = all().iter().map(|d| d.rule_id()).collect();
        let mut sorted = ids.clone();
        sorted.sort_unstable();
        assert_eq!(ids, sorted, "register detectors in rule-id order");
    }
}
