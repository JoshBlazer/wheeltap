//! WT003 — Unchecked arithmetic on balances.
//!
//! Solana programs ship as release builds, and release builds **wrap** on
//! overflow. Rust's debug-build overflow panic is not in the deployed artifact
//! unless the project asks for it.
//!
//! Wrapping is worse than panicking. A panic aborts the transaction and nothing
//! changes; wrapping produces a plausible wrong number and commits it. A deposit
//! becomes a tiny balance, a reward becomes an enormous one, and the program
//! reports success either way.
//!
//! A project that sets `overflow-checks = true` has removed the hazard, and this
//! rule stays quiet for it.

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use wheeltap_core::model::ProgramContext;
use wheeltap_core::source::Location;
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

use crate::body;
use crate::names::{mentions_counter, mentions_value};

#[derive(Default)]
pub struct UncheckedArithmetic;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT003",
    name: "Unchecked arithmetic",
    severity: Severity::High,
    // Medium: without types, a balance is told from an index by its name.
    confidence: Confidence::Medium,
    description: "Arithmetic on a balance can wrap silently in a release build",
    remediation: "Use `checked_add`/`checked_sub`/`checked_mul` and return an error on \
                  overflow, or `saturating_*` where clamping is the intended behaviour. \
                  Alternatively set `overflow-checks = true` under `[profile.release]`, \
                  which turns wrapping into a panic and silences this rule.",
    references: &[
        "https://solana.com/developers/courses/program-security/overflow-underflow",
        "https://doc.rust-lang.org/cargo/reference/profiles.html#overflow-checks",
    ],
};

impl Detector for UncheckedArithmetic {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();
        // Directory to `overflow-checks`, so a scan of a large tree reads each
        // manifest once rather than once per handler.
        let mut manifests: HashMap<PathBuf, bool> = HashMap::new();

        for handler in &ctx.handlers {
            // The manifest that governs this file decides whether wrapping is
            // even possible.
            if overflow_checked(ctx.sources.get(handler.file).path.as_path(), &mut manifests) {
                continue;
            }

            for operation in body::arithmetic(handler) {
                if !is_risky(&operation.text) {
                    continue;
                }

                let at = Location::from_span(handler.file, operation.span);
                findings.push(ctx.finding(
                    &METADATA,
                    at,
                    &handler.item_path,
                    format!(
                        "`{}` in `{}` uses `{}` on a value that holds funds. In a release \
                         build this wraps silently rather than failing.",
                        one_line(&operation.text),
                        handler.name,
                        operation.operator
                    ),
                ));
            }
        }

        findings
    }
}

/// Whether an operation is worth reporting.
///
/// Requires a value-like operand and rejects counting arithmetic. Most
/// arithmetic in a program is indices, lengths, and sizes; reporting those
/// trains people to ignore the rule, and then they ignore the one that mattered.
fn is_risky(text: &str) -> bool {
    mentions_value(text) && !mentions_counter(text)
}

/// Collapse an expression onto one line for the message.
fn one_line(text: &str) -> String {
    let flat = text.split_whitespace().collect::<Vec<_>>().join(" ");
    if flat.chars().count() > 60 {
        let truncated: String = flat.chars().take(57).collect();
        format!("{truncated}...")
    } else {
        flat
    }
}

/// Whether the project governing `file` enables `overflow-checks`.
///
/// Walks up from the file to the nearest `Cargo.toml`, as cargo itself would. A
/// tree with no manifest at all — a bare fixture directory, say — is treated as
/// unchecked, which is the Rust default and the deployed behaviour.
fn overflow_checked(file: &Path, cache: &mut HashMap<PathBuf, bool>) -> bool {
    let Some(dir) = file.parent() else {
        return false;
    };

    if let Some(cached) = cache.get(dir) {
        return *cached;
    }

    let answer = find_manifest(dir).is_some_and(|manifest| manifest_enables_checks(&manifest));
    cache.insert(dir.to_path_buf(), answer);
    answer
}

/// The nearest `Cargo.toml` at or above `dir`.
fn find_manifest(dir: &Path) -> Option<PathBuf> {
    let mut current = Some(dir);
    while let Some(path) = current {
        let candidate = path.join("Cargo.toml");
        if candidate.is_file() {
            return Some(candidate);
        }
        current = path.parent();
    }
    None
}

/// Whether a manifest turns on overflow checks for release builds.
///
/// `[profile.release]` is what ships. A workspace-level `[profile.release]`
/// counts too, since cargo applies the workspace profile to its members.
fn manifest_enables_checks(manifest: &Path) -> bool {
    let Ok(text) = std::fs::read_to_string(manifest) else {
        return false;
    };
    // `toml::Table`, not `toml::Value`: in toml 1.x, parsing a `Value` parses a
    // single value, and a whole manifest is rejected as trailing content.
    let Ok(value) = text.parse::<toml::Table>() else {
        return false;
    };

    ["profile", "workspace"]
        .iter()
        .filter_map(|root| value.get(*root))
        .any(|section| {
            let profile = section
                .get("release")
                .or_else(|| section.get("profile").and_then(|p| p.get("release")));
            profile
                .and_then(|release| release.get("overflow-checks"))
                .and_then(toml::Value::as_bool)
                .unwrap_or(false)
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn value_arithmetic_is_risky_and_counting_arithmetic_is_not() {
        assert!(is_risky("stake.amount + amount"));
        assert!(is_risky("pool.remaining_rewards -= rewards"));
        assert!(is_risky("self.balance * multiplier"));

        assert!(!is_risky("i + 1"));
        assert!(!is_risky("entries.len() - 1"));
        assert!(!is_risky("ANCHOR_DISCRIMINATOR + 8 * MAX_ENTRIES"));
        // A value word alongside a counter word reads as bookkeeping.
        assert!(!is_risky("stake_index + 1"));
    }

    #[test]
    fn manifest_detection_reads_the_release_profile() {
        let dir = tempfile::TempDir::new().expect("tempdir");

        let off = dir.path().join("Cargo.toml");
        std::fs::write(&off, "[package]\nname = \"p\"\n").expect("write");
        assert!(!manifest_enables_checks(&off));

        std::fs::write(
            &off,
            "[package]\nname = \"p\"\n\n[profile.release]\noverflow-checks = true\n",
        )
        .expect("write");
        assert!(manifest_enables_checks(&off));

        std::fs::write(
            &off,
            "[package]\nname = \"p\"\n\n[profile.release]\noverflow-checks = false\n",
        )
        .expect("write");
        assert!(!manifest_enables_checks(&off));
    }

    #[test]
    fn a_malformed_manifest_does_not_panic() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let broken = dir.path().join("Cargo.toml");
        std::fs::write(&broken, "this is not [ valid toml").expect("write");
        assert!(!manifest_enables_checks(&broken));
    }

    #[test]
    fn manifests_are_found_by_walking_upwards() {
        let dir = tempfile::TempDir::new().expect("tempdir");
        let nested = dir.path().join("src/instructions");
        std::fs::create_dir_all(&nested).expect("mkdir");
        std::fs::write(dir.path().join("Cargo.toml"), "[package]\nname = \"p\"\n").expect("write");

        assert_eq!(find_manifest(&nested), Some(dir.path().join("Cargo.toml")));
    }

    #[test]
    fn long_expressions_are_truncated_for_the_message() {
        let long = "a".repeat(100);
        assert_eq!(one_line(&long).chars().count(), 60);
        assert_eq!(one_line("a  +\n  b"), "a + b");
    }
}
