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

/// Whether the two accounts are tied together by the constraints on this
/// instruction, directly or through other accounts.
///
/// Programs build a relationship out of parts. Drift ties a `user_stats` to the
/// `authority` that signs for it in two steps, with a helper predicate on each
/// account:
///
/// ```ignore
/// #[account(mut, constraint = can_sign_for_user(&user, &authority)?)]
/// pub user: AccountLoader<'info, User>,
/// #[account(mut, constraint = is_stats_for_user(&user, &user_stats)?)]
/// pub user_stats: AccountLoader<'info, UserStats>,
/// ```
///
/// Neither constraint names both `user_stats` and `authority`. Reading them one
/// at a time reports ten of drift's account lists as unlinked — and the check
/// it cannot see is the one Trail of Bits asked drift to add (TOB-DRIFT-8,
/// "Missing verification of maker and maker_stats accounts"). So the links are
/// collected into a graph and followed transitively.
///
/// A constraint attached to a field links that field to every other account it
/// names, which also covers derivation: `seeds = [b"t", pool.key().as_ref()]`
/// on one account ties it to `pool`, and an address that was not derived from
/// that key cannot be produced.
///
/// This is evidence, not proof. A constraint asserting two accounts *differ*
/// links them here as surely as one asserting they match. Following the helper
/// into its body would settle it, and that is the boundary ADR-001 draws.
fn related_by_constraint(
    accounts: &wheeltap_core::model::AccountsStruct,
    field: &str,
    target: &str,
) -> bool {
    let names: Vec<&str> = accounts
        .fields
        .iter()
        .map(|other| other.name.as_str())
        .collect();

    let mut edges: Vec<(usize, usize)> = Vec::new();
    for (index, other) in accounts.fields.iter().enumerate() {
        let mut link_to = |text: &str| {
            for (candidate, name) in names.iter().enumerate() {
                if candidate != index && mentions_identifier(text, name) {
                    edges.push((index, candidate));
                }
            }
        };

        // Only the constraints that assert something *relational* create a
        // link. `payer = admin` and `close = destination` name another account
        // without claiming any correspondence between the two, and letting
        // them bridge the graph would silence the rule through accounts that
        // merely paid for each other.
        for constraint in other.constraints.iter() {
            match &constraint.kind {
                ConstraintKind::Custom { expr, .. } => link_to(expr),
                ConstraintKind::Seeds { raw }
                | ConstraintKind::Address { raw }
                | ConstraintKind::Owner { raw } => link_to(raw),
                ConstraintKind::HasOne { target, .. } => link_to(target),
                ConstraintKind::Namespaced {
                    value: Some(value), ..
                } => link_to(value),
                _ => {}
            }
        }
    }

    let Some(from) = names.iter().position(|name| *name == field) else {
        return false;
    };
    let Some(to) = names.iter().position(|name| *name == target) else {
        return false;
    };

    reaches(&edges, names.len(), from, to)
}

/// Whether `from` reaches `to` over the undirected link graph.
fn reaches(edges: &[(usize, usize)], nodes: usize, from: usize, to: usize) -> bool {
    let mut seen = vec![false; nodes];
    let mut queue = vec![from];
    seen[from] = true;

    while let Some(node) = queue.pop() {
        if node == to {
            return true;
        }
        for &(a, b) in edges {
            for (one, other) in [(a, b), (b, a)] {
                if one == node && !seen[other] {
                    seen[other] = true;
                    queue.push(other);
                }
            }
        }
    }

    false
}

/// Whether `text` names `identifier` as a whole word.
///
/// Substring matching cannot be used here: every mention of `user_stats` also
/// contains `user`, so `is_stats_for_user(&user, &user_stats)` would link
/// `user_stats` to an account called `user` whether or not one was named.
fn mentions_identifier(text: &str, identifier: &str) -> bool {
    if identifier.is_empty() {
        return false;
    }
    text.match_indices(identifier).any(|(start, matched)| {
        let before = text[..start].chars().next_back();
        let after = text[start + matched.len()..].chars().next();
        !is_ident_char(before) && !is_ident_char(after)
    })
}

fn is_ident_char(ch: Option<char>) -> bool {
    ch.is_some_and(|c| c.is_ascii_alphanumeric() || c == '_')
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Every mention of `user_stats` contains `user`. Substring matching would
    /// link an account to one that was never named, which is how a whole rule
    /// goes quiet without anyone noticing.
    #[test]
    fn an_identifier_is_matched_as_a_whole_word() {
        let expr = "is_stats_for_user(&user, &user_stats)?";
        assert!(mentions_identifier(expr, "user"));
        assert!(mentions_identifier(expr, "user_stats"));
        assert!(!mentions_identifier(expr, "stats"));
        assert!(!mentions_identifier(expr, "authority"));
    }

    #[test]
    fn an_identifier_inside_a_longer_one_does_not_count() {
        assert!(!mentions_identifier(
            "can_sign_for_user(&user, &authority)",
            "use"
        ));
        assert!(!mentions_identifier("user_stats.load()?", "stats"));
        assert!(mentions_identifier("&user_stats.load()?", "user_stats"));
        assert!(!mentions_identifier("anything", ""));
    }

    #[test]
    fn a_link_graph_is_walked_transitively() {
        // 0—1 and 1—2, so 0 reaches 2 without a direct edge.
        let edges = [(0, 1), (1, 2)];
        assert!(reaches(&edges, 4, 0, 2));
        assert!(reaches(&edges, 4, 2, 0), "links are undirected");
        assert!(
            !reaches(&edges, 4, 0, 3),
            "an unlinked account stays unlinked"
        );
    }

    /// A cycle must not spin forever, and an account always reaches itself.
    #[test]
    fn a_cycle_terminates() {
        let edges = [(0, 1), (1, 2), (2, 0)];
        assert!(reaches(&edges, 3, 0, 2));
        assert!(reaches(&edges, 3, 1, 1));
    }
}
