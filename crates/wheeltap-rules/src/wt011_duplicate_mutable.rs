//! WT011 — Duplicate mutable accounts.
//!
//! Two account fields of the same type can be given the same address. Anchor
//! deserialises the account twice, into two independent in-memory copies, and
//! the handler mutates both. Whichever copy is serialised back last wins, so the
//! other's changes vanish.
//!
//! In a transfer that means debiting one copy and crediting the other, then
//! discarding the debit.

use std::collections::BTreeMap;

use wheeltap_core::model::constraints::ConstraintKind;
use wheeltap_core::model::{AccountsStruct, ProgramContext};
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

pub struct DuplicateMutable;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT011",
    name: "Duplicate mutable accounts",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "Two mutable accounts of the same type may be given the same address",
    remediation: "Assert that the accounts differ: \
                  `constraint = first.key() != second.key()`. Anchor cannot infer it, because \
                  passing the same account twice is legitimate in other instructions.",
    references: &[
        "https://solana.com/developers/courses/program-security/duplicate-mutable-accounts",
        "https://github.com/coral-xyz/sealevel-attacks",
    ],
};

impl Detector for DuplicateMutable {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for accounts in &ctx.accounts {
            // Group the *mutable* accounts by the state type they hold. Only a
            // written account can lose an update to its twin.
            let mut by_type: BTreeMap<&str, Vec<&wheeltap_core::model::AccountField>> =
                BTreeMap::new();
            for field in &accounts.fields {
                if !field.constraints.is_mut() {
                    continue;
                }
                let Some(inner) = field.ty.inner() else {
                    continue;
                };
                if ctx.state(inner).is_none() {
                    continue;
                }
                by_type.entry(inner).or_default().push(field);
            }

            for (state, group) in by_type {
                if group.len() < 2 {
                    continue;
                }
                if distinguished(accounts, &group)
                    || distinguished_in_handler(ctx, &accounts.name, &group)
                {
                    continue;
                }

                let names: Vec<&str> = group.iter().map(|f| f.name.as_str()).collect();
                findings.push(ctx.finding(
                    &METADATA,
                    group[0].location,
                    &group[0].item_path,
                    format!(
                        "`{}` takes {} mutable `{state}` accounts ({}) with nothing asserting \
                         they differ. A caller can pass the same address for all of them; \
                         Anchor deserialises it once per field, and only the last write \
                         survives.",
                        accounts.name,
                        group.len(),
                        names.join(", ")
                    ),
                ));
            }
        }

        findings
    }
}

/// Whether any constraint distinguishes the accounts in the group.
///
/// A single constraint naming two of them is enough. Programs write this as
/// `first.key() != second.key()`, and also factor it into helpers, so naming
/// both is the signal rather than the exact comparison.
fn distinguished(accounts: &AccountsStruct, group: &[&wheeltap_core::model::AccountField]) -> bool {
    accounts.fields.iter().any(|field| {
        field.constraints.any(|kind| match kind {
            ConstraintKind::Custom { expr, .. } => {
                group.iter().filter(|f| expr.contains(&f.name)).count() >= 2
            }
            // Two PDAs with different seeds cannot be the same address.
            ConstraintKind::Seeds { .. } => group.iter().all(|f| f.constraints.is_pda()),
            _ => false,
        })
    })
}

/// Whether a handler asserts the accounts differ.
///
/// Anchor constraints are one place to do this; the handler is the other, and
/// drift uses the handler:
///
/// ```ignore
/// let from_user_key = ctx.accounts.from_user.key();
/// let to_user_key = ctx.accounts.to_user.key();
/// validate!(from_user_key != to_user_key, ErrorCode::CannotTransferToSelf)?;
/// ```
///
/// Checking constraints alone reported all twelve of drift's transfer and
/// liquidation instructions, every one of which does exactly this.
fn distinguished_in_handler(
    ctx: &ProgramContext,
    accounts: &str,
    group: &[&wheeltap_core::model::AccountField],
) -> bool {
    ctx.handlers_for(accounts).any(|handler| {
        let body = crate::body::text(handler);
        // An inequality somewhere in a handler that touches both accounts. The
        // comparison is usually against locals rather than the fields directly,
        // so requiring the exact expression would miss it.
        body.contains("!=")
            && group
                .iter()
                .all(|field| body.contains(&format!("accounts.{}", field.name)))
    })
}
