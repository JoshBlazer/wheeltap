//! WT014 — Unrelated remaining accounts.
//!
//! Two accounts taken from `ctx.remaining_accounts` and deserialised into
//! different program state types that both record an authority, with nothing
//! checking that the authorities match.
//!
//! This is TOB-DRIFT-8. Drift loaded a maker's `User` and `UserStats` from the
//! remaining accounts and used them together; nothing established that they
//! belonged to the same trader, so a caller could pass one trader's account
//! with another's statistics. Accounts in `#[derive(Accounts)]` would get a
//! `has_one` or a seed for this. Remaining accounts get nothing unless the
//! program writes it, which is why the rule exists separately from WT005.
//!
//! **What counts as relating them.** A comparison naming the shared field on
//! both sides — `a.authority == b.authority`, `.eq(..)`, `!=`, or
//! `require_keys_eq!` — in the function that loads them or in any function
//! that calls it. Drift's referrer handling checks in the caller, and is
//! correct.
//!
//! **What is not a pair.** Reads inside a loop are one of a collection, the
//! shape of a map loader, and accounts sharing a non-authority field such as
//! `mint` are not claimed to belong together.

use std::collections::BTreeSet;

use wheeltap_core::model::ProgramContext;
use wheeltap_core::model::remaining::{Function, RemainingRead};
use wheeltap_core::model::ty::render_stream;
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

use crate::names;

pub struct UnrelatedRemainingAccounts;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT014",
    name: "Unrelated remaining accounts",
    severity: Severity::High,
    confidence: Confidence::Medium,
    description: "Two remaining accounts that both record an authority are used together without \
                  checking that it matches",
    remediation: "Compare the stored authorities before using the accounts together: \
                  `require_keys_eq!(a.load()?.authority, b.load()?.authority)`. Where the pair \
                  has a fixed relationship, deriving one account's address from the other with \
                  `Pubkey::find_program_address` and comparing keys is stronger still.",
    references: &[
        "https://github.com/trailofbits/publications/blob/master/reviews/2023-02-driftv2-securityreview.pdf",
        "https://www.anchor-lang.com/docs/references/account-types",
    ],
};

impl Detector for UnrelatedRemainingAccounts {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for (index, function) in ctx.functions.iter().enumerate() {
            let reads: Vec<&RemainingRead> = ctx
                .remaining
                .iter()
                .filter(|read| read.function == index && !read.in_loop)
                .collect();

            for (later, second) in reads.iter().enumerate() {
                for first in &reads[..later] {
                    if first.state == second.state {
                        continue;
                    }
                    for field in shared_authorities(ctx, function, first, second) {
                        if related(ctx, function, &field) {
                            continue;
                        }
                        findings.push(ctx.finding(
                            &METADATA,
                            second.location,
                            &format!("{}.{}", function.item_path, second.binding),
                            format!(
                                "`{}` takes `{}` (`{}`) and `{}` (`{}`) from the remaining \
                                 accounts. Both record `{field}`, and nothing compares them, in \
                                 `{}` or in anything that calls it. A caller can pass one \
                                 owner's `{}` with another owner's `{}`.",
                                function.name,
                                first.binding,
                                first.state,
                                second.binding,
                                second.state,
                                function.name,
                                first.state,
                                second.state,
                            ),
                        ));
                    }
                }
            }
        }

        findings
    }
}

/// Authority-like `Pubkey` fields both state types record.
fn shared_authorities(
    ctx: &ProgramContext,
    function: &Function,
    first: &RemainingRead,
    second: &RemainingRead,
) -> Vec<String> {
    let keys = |name: &str| -> BTreeSet<String> {
        ctx.state(name, function.file)
            .map(|state| {
                state
                    .fields
                    .iter()
                    .filter(|(field, ty)| ty == "Pubkey" && names::is_authority_like(field))
                    .map(|(field, _)| field.clone())
                    .collect()
            })
            .unwrap_or_default()
    };
    keys(&first.state)
        .intersection(&keys(&second.state))
        .cloned()
        .collect()
}

/// Whether the loading function, or any function calling it, compares the
/// field on both sides of one expression.
fn related(ctx: &ProgramContext, function: &Function, field: &str) -> bool {
    let call = format!("{}(", function.name);
    std::iter::once(function)
        .chain(
            ctx.functions
                .iter()
                .filter(|f| !std::ptr::eq(*f, function) && calls(&text(f), &call)),
        )
        .any(|f| compares(&text(f), field))
}

fn text(function: &Function) -> String {
    render_stream(&quote::ToTokens::to_token_stream(&function.block))
}

/// Whether `body` calls the function, not merely a longer name ending in it.
fn calls(body: &str, call: &str) -> bool {
    body.match_indices(call).any(|(at, _)| {
        !body[..at]
            .chars()
            .next_back()
            .is_some_and(|c| c.is_alphanumeric() || c == '_')
    })
}

/// Whether one statement mentions `.field` twice alongside a comparison.
fn compares(body: &str, field: &str) -> bool {
    let member = format!(".{field}");
    body.split([';', '{', '}']).any(|statement| {
        let mentions = statement
            .match_indices(&member)
            .filter(|(at, _)| {
                !statement[at + member.len()..]
                    .chars()
                    .next()
                    .is_some_and(|c| c.is_alphanumeric() || c == '_')
            })
            .count();
        mentions >= 2
            && ["==", "!=", ".eq(", "require_keys_eq", "require_keys_neq"]
                .iter()
                .any(|op| statement.contains(op))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_comparison_must_name_the_field_on_both_sides() {
        assert!(compares(
            "validate!(a.authority == b.authority, E)",
            "authority"
        ));
        assert!(compares(
            "require_keys_eq!(a.load()?.authority, b.load()?.authority)",
            "authority"
        ));
        assert!(!compares(
            "validate!(a.authority == key, E); x = b.authority",
            "authority"
        ));
        assert!(!compares(
            "a.authority_bump == b.authority_bump",
            "authority"
        ));
    }

    #[test]
    fn a_call_is_a_whole_name() {
        assert!(calls("let x = get_pair(iter)?", "get_pair("));
        assert!(!calls("let x = try_get_pair(iter)?", "get_pair("));
    }
}
