//! Which accounts in one instruction are tied to which others.
//!
//! Programs rarely state a relationship in a single place. Drift ties a
//! `user_stats` to the `authority` that signs for it in two steps, with a
//! helper predicate on each account:
//!
//! ```ignore
//! #[account(mut, constraint = can_sign_for_user(&user, &authority)?)]
//! pub user: AccountLoader<'info, User>,
//! #[account(mut, constraint = is_stats_for_user(&user, &user_stats)?)]
//! pub user_stats: AccountLoader<'info, UserStats>,
//! ```
//!
//! Neither constraint names both `user_stats` and `authority`. Reading them one
//! at a time called ten of drift's account lists unlinked, and the check that
//! could not be seen was the one Trail of Bits had asked drift to add
//! (TOB-DRIFT-8). So the links are collected into a graph and followed
//! transitively.
//!
//! Two rules ask different questions of the same graph. WT005 asks whether two
//! accounts are tied together at all. WT011 asks the opposite — whether two
//! accounts of the same type are kept apart — and uses the graph to find the
//! accounts each one *stands for*, because a program that rejects
//! self-liquidation compares the two users, not their statistics.
//!
//! This is evidence, not proof. A constraint asserting two accounts differ
//! links them here as surely as one asserting they match. Following the helper
//! into its body would settle it; that is the boundary ADR-001 draws.

use wheeltap_core::model::AccountsStruct;
use wheeltap_core::model::constraints::ConstraintKind;

/// The accounts of one instruction, and which of them are tied together.
pub struct Links<'a> {
    names: Vec<&'a str>,
    edges: Vec<(usize, usize)>,
}

impl<'a> Links<'a> {
    /// Build the graph for an instruction's account list.
    #[must_use]
    pub fn of(accounts: &'a AccountsStruct) -> Self {
        let names: Vec<&str> = accounts
            .fields
            .iter()
            .map(|field| field.name.as_str())
            .collect();
        let mut edges = Vec::new();

        for (index, field) in accounts.fields.iter().enumerate() {
            let mut link_to = |text: &str| {
                for (candidate, name) in names.iter().enumerate() {
                    if candidate != index && mentions_identifier(text, name) {
                        edges.push((index, candidate));
                    }
                }
            };

            // Only constraints that assert something *relational* create a
            // link. `payer = admin` and `close = destination` name another
            // account without claiming any correspondence between the two, and
            // letting them bridge the graph would tie together accounts that
            // merely paid for each other.
            for constraint in field.constraints.iter() {
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

        Self { names, edges }
    }

    /// Whether two accounts are tied together, directly or through others.
    #[must_use]
    pub fn related(&self, one: &str, other: &str) -> bool {
        match (self.index(one), self.index(other)) {
            (Some(from), Some(to)) => self.component(from).contains(&to),
            _ => false,
        }
    }

    /// Every account tied to this one, including itself.
    ///
    /// These are the accounts it stands for: a check on any of them is a check
    /// that constrains this one too.
    #[must_use]
    pub fn standing_for(&self, name: &str) -> Vec<&'a str> {
        let Some(start) = self.index(name) else {
            return Vec::new();
        };
        self.component(start)
            .into_iter()
            .map(|index| self.names[index])
            .collect()
    }

    fn index(&self, name: &str) -> Option<usize> {
        self.names.iter().position(|candidate| *candidate == name)
    }

    /// Every node reachable from `start`, including `start` itself.
    fn component(&self, start: usize) -> Vec<usize> {
        let mut seen = vec![false; self.names.len()];
        let mut queue = vec![start];
        let mut found = Vec::new();
        seen[start] = true;

        while let Some(node) = queue.pop() {
            found.push(node);
            for &(a, b) in &self.edges {
                for (one, other) in [(a, b), (b, a)] {
                    if one == node && !seen[other] {
                        seen[other] = true;
                        queue.push(other);
                    }
                }
            }
        }

        found
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// Parse one source string into its first `#[derive(Accounts)]` struct.
    fn accounts(source: &str) -> AccountsStruct {
        let dir = tempfile::tempdir().expect("tempdir");
        std::fs::write(dir.path().join("lib.rs"), source).expect("write");
        let ctx = wheeltap_core::ProgramContext::scan(dir.path());
        ctx.accounts
            .into_iter()
            .next()
            .expect("one accounts struct")
    }

    const DRIFT_SHAPE: &str = r#"
        #[derive(Accounts)]
        pub struct PlaceOrder<'info> {
            #[account(mut, constraint = can_sign_for_user(&user, &authority)?)]
            pub user: AccountLoader<'info, User>,
            #[account(mut, constraint = is_stats_for_user(&user, &user_stats)?)]
            pub user_stats: AccountLoader<'info, UserStats>,
            pub authority: Signer<'info>,
            #[account(mut)]
            pub vault: Account<'info, Vault>,
        }
    "#;

    #[test]
    fn a_relationship_built_in_two_steps_is_followed() {
        let accounts = accounts(DRIFT_SHAPE);
        let links = Links::of(&accounts);

        assert!(
            links.related("user", "authority"),
            "named by one constraint"
        );
        assert!(links.related("user_stats", "user"), "named by the other");
        assert!(
            links.related("user_stats", "authority"),
            "and so, transitively, by the pair"
        );
    }

    #[test]
    fn an_account_no_constraint_names_stays_unrelated() {
        let accounts = accounts(DRIFT_SHAPE);
        let links = Links::of(&accounts);

        assert!(!links.related("vault", "user"));
        assert!(!links.related("vault", "authority"));
        assert_eq!(links.standing_for("vault"), ["vault"]);
    }

    #[test]
    fn an_account_stands_for_everything_tied_to_it() {
        let accounts = accounts(DRIFT_SHAPE);
        let mut standing = Links::of(&accounts).standing_for("user_stats");
        standing.sort_unstable();

        assert_eq!(standing, ["authority", "user", "user_stats"]);
    }

    #[test]
    fn an_unknown_account_is_related_to_nothing() {
        let accounts = accounts(DRIFT_SHAPE);
        let links = Links::of(&accounts);

        assert!(!links.related("absent", "user"));
        assert!(links.standing_for("absent").is_empty());
    }

    /// `payer` and `close` name another account without asserting anything
    /// about the pair. Letting them bridge the graph would tie together
    /// accounts that merely paid for each other.
    #[test]
    fn non_relational_constraints_do_not_link() {
        let accounts = accounts(
            r#"
            #[derive(Accounts)]
            pub struct Create<'info> {
                #[account(init, payer = payer, space = 64)]
                pub thing: Account<'info, Thing>,
                #[account(mut)]
                pub payer: Signer<'info>,
                #[account(mut, close = payer)]
                pub old: Account<'info, Thing>,
            }
        "#,
        );
        let links = Links::of(&accounts);

        assert!(!links.related("thing", "payer"));
        assert!(!links.related("old", "payer"));
    }

    #[test]
    fn derivation_links_an_account_to_its_seed() {
        let accounts = accounts(
            r#"
            #[derive(Accounts)]
            pub struct AddConstituent<'info> {
                #[account(mut)]
                pub lp_pool: AccountLoader<'info, LpPool>,
                #[account(mut, seeds = [b"target", lp_pool.key().as_ref()], bump)]
                pub target: AccountLoader<'info, Target>,
            }
        "#,
        );

        assert!(
            Links::of(&accounts).related("lp_pool", "target"),
            "an address derived from a key cannot be mismatched"
        );
    }

    #[test]
    fn identifiers_are_matched_as_whole_words() {
        let expr = "is_stats_for_user(&user, &user_stats)?";
        assert!(mentions_identifier(expr, "user"));
        assert!(mentions_identifier(expr, "user_stats"));
        assert!(!mentions_identifier(expr, "stats"));
        assert!(!mentions_identifier(expr, "authority"));
        assert!(!mentions_identifier("anything", ""));
    }
}
