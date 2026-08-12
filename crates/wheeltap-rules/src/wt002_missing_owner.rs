//! WT002 — Missing owner check.
//!
//! Account data is just bytes. The only thing separating a real price feed from
//! one an attacker fabricated is the program that owns it — so deserialising an
//! account without establishing its owner is reading attacker-authored state as
//! though it were your own.
//!
//! The rule fires on the *read*, not on the declaration. An `AccountInfo` held
//! only to hand to a CPI is entirely ordinary, and flagging those would bury the
//! findings that matter.

use wheeltap_core::model::{AccountField, ProgramContext};
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

use crate::body;

pub struct MissingOwner;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT002",
    name: "Missing owner check",
    severity: Severity::Critical,
    // Medium, not high: the owner assertion is looked for in the handler that
    // does the read, so a check made in a called function is missed (ADR-001).
    confidence: Confidence::Medium,
    description: "Account data is deserialised without verifying the owning program",
    remediation: "Use `Account<'info, T>`, which verifies the owner and discriminator \
                  before the handler runs. If the account must stay an `AccountInfo`, \
                  pin it with `#[account(owner = expected::ID)]` or assert \
                  `*account.owner` before reading its data.",
    references: &[
        "https://solana.com/developers/courses/program-security/owner-checks",
        "https://github.com/coral-xyz/sealevel-attacks",
    ],
};

impl Detector for MissingOwner {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for accounts in &ctx.accounts {
            let candidates: Vec<&AccountField> =
                accounts.fields.iter().filter(|f| is_candidate(f)).collect();
            if candidates.is_empty() {
                continue;
            }

            // Only handlers that actually operate on this account list can read
            // these accounts.
            for handler in ctx.handlers_for(&accounts.name) {
                let body = body::text(handler);

                for field in &candidates {
                    if !body::reads_account_data(&body, &field.name) {
                        continue;
                    }
                    if body::asserts_owner(&body, &field.name) {
                        continue;
                    }

                    findings.push(ctx.finding(
                        &METADATA,
                        field.location,
                        &field.item_path,
                        format!(
                            "`{}.{}` is an unvalidated account whose data is deserialised in \
                             `{}` without establishing the owning program. An attacker can pass \
                             an account owned by their own program with any contents they like.",
                            accounts.name, field.name, handler.name
                        ),
                    ));
                }
            }
        }

        findings
    }
}

/// Whether a field could be a missing-owner-check candidate at all.
///
/// The account must be one Anchor validates nothing about, and must not already
/// establish its owner or its exact address by constraint.
fn is_candidate(field: &AccountField) -> bool {
    field.ty.is_unchecked()
        && !field.constraints.asserts_owner()
        && !field.constraints.asserts_address()
}
