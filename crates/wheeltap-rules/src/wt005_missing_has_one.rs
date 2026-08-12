//! WT005 — A stored relationship that is never enforced.
//!
//! When an account struct stores `authority: Pubkey`, that field is a claim:
//! *this* account belongs to *that* key. If the same instruction takes both the
//! account and an account by that name, and never compares them, the claim is
//! documentation rather than a check.
//!
//! This rule is the one that most depends on the program model rather than on
//! syntax: it holds the `#[account]` state structs on one side and the
//! `#[derive(Accounts)]` lists on the other, and looks for a `Pubkey` field
//! named like an account that appears in the same instruction.

use wheeltap_core::model::constraints::ConstraintKind;
use wheeltap_core::model::{AccountField, ProgramContext};
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

pub struct MissingHasOne;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT005",
    name: "Missing has_one constraint",
    severity: Severity::High,
    confidence: Confidence::Medium,
    description: "An account stores a key that the instruction never checks it against",
    remediation: "Add `has_one = <field>` to the account that stores the key, or assert it \
                  explicitly with `constraint = account.field == other.key()`. Deriving the \
                  account's address from the key with `seeds` enforces the same relationship \
                  and is stronger still.",
    references: &[
        "https://solana.com/developers/courses/program-security/account-data-matching",
        "https://www.anchor-lang.com/docs/account-constraints",
    ],
};

impl Detector for MissingHasOne {
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
                if !is_candidate(field) {
                    continue;
                }

                // The account must be one of this program's state accounts, so
                // that we can see what keys it stores.
                let Some(state) = field.ty.inner().and_then(|inner| ctx.state(inner)) else {
                    continue;
                };

                // An instruction holding two accounts of the same state type is
                // acting for two parties, and which one a same-named account
                // belongs to is a question about intent. Drift's `FillOrder`
                // takes a `filler` and a `user`, both `AccountLoader<User>`,
                // and its `authority` signs for the filler only — so `user`
                // deliberately has no relationship to it.
                if same_type_siblings(ctx, accounts, &state.name) > 1 {
                    continue;
                }

                for (stored_name, stored_type) in &state.fields {
                    if !is_pubkey(stored_type) {
                        continue;
                    }
                    // The relationship only matters if the counterparty is
                    // present in this same instruction.
                    if accounts.field(stored_name).is_none() {
                        continue;
                    }
                    if enforces(field, stored_name)
                        || enforced_elsewhere(ctx, accounts, &field.name, stored_name)
                        || related_by_constraint(accounts, &field.name, stored_name)
                    {
                        continue;
                    }

                    findings.push(ctx.finding(
                        &METADATA,
                        field.location,
                        &field.item_path,
                        format!(
                            "`{}` stores `{}: Pubkey`, and `{}` takes both `{}` and `{}`, but \
                             never checks that they match. The stored key records a \
                             relationship the instruction does not enforce, so any `{}` can be \
                             used with any `{}`.",
                            state.name,
                            stored_name,
                            accounts.name,
                            field.name,
                            stored_name,
                            field.name,
                            stored_name
                        ),
                    ));
                }
            }
        }

        findings
    }
}

/// Whether an account is one whose stored relationships can be checked at all.
///
/// Two exclusions, both learned from the corpus:
///
/// - **An account being created has no prior state.** `init` means the handler
///   is about to *write* those keys, so there is nothing to verify them against.
///   Requiring `has_one` on an `init` account asks the program to check a value
///   it is in the middle of assigning. This alone accounted for escrow's only
///   finding and a large share of drift's.
/// - **An account that is not written is a weaker case.** The hazard this rule
///   describes is acting on an account whose counterparty does not belong to it,
///   so the rule confines itself to accounts the instruction modifies.
fn is_candidate(field: &AccountField) -> bool {
    !field.constraints.is_init()
        && !field.constraints.any(|k| matches!(k, ConstraintKind::Zero))
        && field.constraints.is_mut()
}

/// Whether a rendered type is a `Pubkey`.
fn is_pubkey(ty: &str) -> bool {
    ty == "Pubkey" || ty.ends_with("::Pubkey")
}

/// Whether the relationship is enforced anywhere other than on the account
/// that stores it.
///
/// Anchor lets the assertion sit on either side, and real programs regularly put
/// it on the counterparty:
///
/// ```ignore
/// #[account(mut)]
/// pub state: Box<Account<'info, State>>,
/// #[account(constraint = admin.key() == state.admin)]
/// pub admin: Signer<'info>,
/// ```
///
/// A rule that only reads the storing account's constraints calls that a High
/// finding. Drift writes it this way 65 times.
///
/// The handler body counts too, for the same reason WT002 reads bodies: a
/// `require_keys_eq!(state.admin, admin.key())` inside a macro is invisible to
/// any constraint-level check.
fn enforced_elsewhere(
    ctx: &ProgramContext,
    accounts: &wheeltap_core::model::AccountsStruct,
    field: &str,
    target: &str,
) -> bool {
    let accesses = accesses(field, target);
    let mentions = |text: &str| accesses.iter().any(|access| text.contains(access));

    let in_constraints = accounts.fields.iter().any(|other| {
        other.constraints.any(|kind| match kind {
            ConstraintKind::Custom { expr, .. } => mentions(expr),
            ConstraintKind::Seeds { raw } | ConstraintKind::Address { raw } => mentions(raw),
            _ => false,
        })
    });
    if in_constraints {
        return true;
    }

    ctx.handlers_for(&accounts.name)
        .any(|handler| mentions(&crate::body::text(handler)))
}

/// How many accounts in this list hold the same state type.
fn same_type_siblings(
    ctx: &ProgramContext,
    accounts: &wheeltap_core::model::AccountsStruct,
    state: &str,
) -> usize {
    accounts
        .fields
        .iter()
        .filter(|field| {
            field
                .ty
                .inner()
                .and_then(|inner| ctx.state(inner))
                .is_some_and(|s| s.name == state)
        })
        .count()
}

/// Whether any constraint relates the two accounts, however indirectly.
///
/// Programs factor repeated checks into helpers — drift writes
/// `constraint = can_sign_for_user(&filler, &authority)?` — and the assertion
/// then lives in a function this analyser does not follow (ADR-001). A
/// constraint naming both accounts is strong evidence that the relationship is
/// the helper's business, and treating it as enforced is the right side to err
/// on.
fn related_by_constraint(
    accounts: &wheeltap_core::model::AccountsStruct,
    field: &str,
    target: &str,
) -> bool {
    accounts.fields.iter().any(|other| {
        other.constraints.any(|kind| match kind {
            ConstraintKind::Custom { expr, .. } => expr.contains(field) && expr.contains(target),
            _ => false,
        })
    })
}

/// The ways a stored key is reached in source.
///
/// The direct form is `state.admin`. Zero-copy accounts interpose a loader —
/// `user.load()?.authority` — and drift, which is almost entirely zero-copy,
/// writes it that way 52 times. A needle that only matches the direct form
/// reports every one of them.
fn accesses(field: &str, target: &str) -> Vec<String> {
    [
        format!("{field}.{target}"),
        format!("{field}.load()?.{target}"),
        format!("{field}.load_mut()?.{target}"),
        format!("{field}.load_init()?.{target}"),
    ]
    .into_iter()
    .collect()
}

/// Whether the field's own constraints enforce the relationship.
///
/// Three spellings count, and missing any of them reports correct code:
///
/// - `has_one = target`, the idiomatic form;
/// - a custom `constraint` mentioning the target, which is what programs write
///   when they need a domain-specific error;
/// - `seeds` derived from the target, which is stronger than a comparison —
///   an address that was not derived from that key cannot be produced.
fn enforces(field: &AccountField, target: &str) -> bool {
    if field.constraints.has_one_targets().contains(&target) {
        return true;
    }

    field.constraints.any(|kind| match kind {
        ConstraintKind::Custom { expr, .. } => expr.contains(target),
        ConstraintKind::Seeds { raw } => raw.contains(target),
        ConstraintKind::Address { raw } => raw.contains(target),
        _ => false,
    })
}
