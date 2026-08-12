//! WT001 — Missing signer check.
//!
//! Two questions get confused constantly, and the confusion is the bug:
//!
//! - **Who is this account?** — answered by `has_one`, `address`, or seeds.
//! - **Did they authorise this?** — answered *only* by a signature.
//!
//! An account list that answers the first and skips the second is an access
//! control that checks the name on the door and never asks for the key.

use std::collections::HashSet;

use wheeltap_core::model::{AccountField, AccountsStruct, ProgramContext};
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

use crate::names::is_authority_like;

pub struct MissingSigner;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT001",
    name: "Missing signer check",
    severity: Severity::Critical,
    confidence: Confidence::High,
    description: "An account treated as an authority is never required to sign",
    remediation: "Type the account as `Signer<'info>`. If it must stay an \
                  `AccountInfo`, require the signature explicitly with \
                  `#[account(signer)]` or `constraint = authority.is_signer`.",
    references: &[
        "https://solana.com/developers/courses/program-security/signer-auth",
        "https://github.com/coral-xyz/sealevel-attacks",
    ],
};

impl Detector for MissingSigner {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for accounts in &ctx.accounts {
            // If anything in the account list signs, the instruction has *an*
            // authoriser. Whether it is the *right* one is a judgement about
            // intent that a syntactic linter cannot make, and guessing at it is
            // what produces critical-severity noise. See `is_unsigned` below.
            if signs_somewhere(accounts) {
                continue;
            }

            let relationship_targets = has_one_targets(accounts);

            for field in &accounts.fields {
                if !is_unsigned_authority(field, &relationship_targets) {
                    continue;
                }

                findings.push(ctx.finding(
                    &METADATA,
                    field.location,
                    &field.item_path,
                    format!(
                        "`{}.{}` is verified by a `has_one` constraint but is never required to \
                         sign, and no account in `{}` signs at all. The constraint proves which \
                         account this is; it does not prove the holder authorised anything. \
                         Public keys are public, so any caller can pass this one.",
                        accounts.name, field.name, accounts.name
                    ),
                ));
            }
        }

        findings
    }
}

/// Whether any account in the list is required to sign.
///
/// This is the condition that separates "nobody authorised this instruction"
/// from "somebody authorised it, and deciding whether it was the right somebody
/// needs a human". Measured against the corpus, it is the difference between
/// nine false positives and none: drift administers user accounts through a
/// `keeper` or `payer` signer while the recorded `authority` never signs, which
/// is correct — initialising or sweeping an account on someone's behalf does not
/// need their consent.
fn signs_somewhere(accounts: &AccountsStruct) -> bool {
    accounts
        .fields
        .iter()
        .any(|field| field.ty.is_signer_checked() || field.constraints.asserts_signer())
}

/// Whether a field is an authority that is verified but never authorised.
fn is_unsigned_authority(field: &AccountField, relationship_targets: &HashSet<&str>) -> bool {
    // Already required to sign, by type or by constraint. Nothing to say.
    if field.ty.is_signer_checked() || field.constraints.asserts_signer() {
        return false;
    }

    // A program-derived address cannot sign, and must not be asked to. No
    // private key exists for it; the program signs on its behalf with the
    // derivation seeds. Without this exclusion, every PDA authority in every
    // real program is a critical finding and the tool is uninstalled within the
    // hour.
    if field.constraints.is_pda() {
        return false;
    }

    // An account pinned to a fixed address is identified by the runtime, and is
    // typically a program or sysvar rather than a caller.
    if field.constraints.asserts_address() {
        return false;
    }

    // The target of a `has_one`: the program went to the trouble of proving
    // *which* account this is, so it matters here -- but proving identity is not
    // authorisation.
    //
    // `has_one` expresses any recorded relationship, so this requires the target
    // to look like an authority too: either unvalidated, or named as one. A pool
    // recording `has_one = mint` on an `Account<'info, Mint>` is not reported.
    relationship_targets.contains(field.name.as_str())
        && (field.ty.is_unchecked() || is_authority_like(&field.name))
}

/// Every account named as the target of a `has_one` anywhere in the struct.
fn has_one_targets(accounts: &AccountsStruct) -> HashSet<&str> {
    accounts
        .fields
        .iter()
        .flat_map(|field| field.constraints.has_one_targets())
        .collect()
}
