//! WT009 — Sysvar spoofing.
//!
//! Sysvars are ordinary accounts at fixed, well-known addresses. Nothing about
//! passing one is privileged, so a caller can pass a different account instead
//! and the program will read whatever it contains.
//!
//! A substituted clock unlocks a vesting schedule that has not vested. A
//! substituted rent sysvar defeats a rent-exemption check. `Sysvar<'info, T>`
//! asserts the address, and so does `#[account(address = sysvar::clock::ID)]`.

use wheeltap_core::model::ProgramContext;
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

pub struct SysvarSpoofing;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT009",
    name: "Sysvar spoofing",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "A sysvar is accepted as an unchecked account with no address constraint",
    remediation: "Use `Sysvar<'info, Clock>` and its siblings, which assert the address. \
                  For sysvars Anchor has no type for, pin it with \
                  `#[account(address = sysvar::instructions::ID)]`.",
    references: &[
        "https://solana.com/developers/courses/program-security/sysvar-spoofing",
        "https://docs.rs/anchor-lang/latest/anchor_lang/accounts/sysvar/struct.Sysvar.html",
    ],
};

/// Field names that denote a sysvar.
///
/// Matched whole, against the field name only. `clock_authority` is a plain
/// account that happens to contain the word and must not be flagged, which is
/// why this is an equality test rather than a substring search.
const SYSVAR_NAMES: &[&str] = &[
    "clock",
    "rent",
    "instructions",
    "sysvar_instructions",
    "slot_hashes",
    "slot_history",
    "recent_blockhashes",
    "epoch_schedule",
    "stake_history",
    "fees",
];

impl Detector for SysvarSpoofing {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for accounts in &ctx.accounts {
            for field in &accounts.fields {
                if !is_sysvar_name(&field.name) {
                    continue;
                }
                // `Sysvar<'info, T>` already asserts the address, and so does an
                // explicit `address =`.
                if !field.ty.is_unchecked() || field.constraints.asserts_address() {
                    continue;
                }

                findings.push(ctx.finding(
                    &METADATA,
                    field.location,
                    &field.item_path,
                    format!(
                        "`{}.{}` is named for a sysvar but is an unchecked account with no \
                         address constraint. Sysvars live at fixed addresses and are otherwise \
                         ordinary accounts, so a caller can substitute one with contents of \
                         their choosing.",
                        accounts.name, field.name
                    ),
                ));
            }
        }

        findings
    }
}

/// Whether a field name *is* a sysvar name, rather than merely containing one.
fn is_sysvar_name(name: &str) -> bool {
    SYSVAR_NAMES.contains(&name)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sysvar_names_match_whole_names_only() {
        assert!(is_sysvar_name("clock"));
        assert!(is_sysvar_name("rent"));
        assert!(is_sysvar_name("slot_hashes"));

        // Plain accounts that merely contain the word.
        assert!(!is_sysvar_name("clock_authority"));
        assert!(!is_sysvar_name("rent_collector"));
        assert!(!is_sysvar_name("rent_payer"));
        assert!(!is_sysvar_name("instructions_data"));
    }
}
