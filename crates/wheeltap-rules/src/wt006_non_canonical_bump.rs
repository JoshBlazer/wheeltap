//! WT006 — Non-canonical PDA bump.
//!
//! `find_program_address` returns the *canonical* bump: the highest byte that
//! puts the derived address off the ed25519 curve. It is not the only byte that
//! works — several usually produce valid, distinct addresses for the same seeds.
//!
//! Taking the bump from instruction data therefore lets the caller choose which
//! of those addresses to use. They can create a second and third account for the
//! same logical seeds, each satisfying every constraint, none of them the one the
//! program's other instructions will find.
//!
//! The distinction that makes this rule usable is between *instruction data* and
//! *stored state*. `bump = market.bump` reads back the canonical bump the
//! program itself saved at creation; it appears 147 times in drift alone, and
//! flagging it would make the rule useless.

use wheeltap_core::model::constraints::ConstraintKind;
use wheeltap_core::model::{AccountsStruct, ProgramContext};
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

pub struct NonCanonicalBump;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT006",
    name: "Non-canonical PDA bump",
    severity: Severity::High,
    confidence: Confidence::High,
    description: "A PDA bump comes from instruction data rather than being derived",
    remediation: "Write `bump` on its own and let Anchor derive the canonical bump, storing \
                  `ctx.bumps.<account>` if later instructions need it. Where a bump is \
                  re-derived, read it from the account (`bump = account.bump`) rather than \
                  from the caller.",
    references: &[
        "https://solana.com/developers/courses/program-security/bump-seed-canonicalization",
        "https://www.anchor-lang.com/docs/pdas",
    ],
};

impl Detector for NonCanonicalBump {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for accounts in &ctx.accounts {
            let arguments = instruction_arguments(accounts);
            if arguments.is_empty() {
                continue;
            }

            for field in &accounts.fields {
                let Some(bump) = field
                    .constraints
                    .find(|k| matches!(k, ConstraintKind::Bump { .. }))
                else {
                    continue;
                };
                let ConstraintKind::Bump { value: Some(value) } = &bump.kind else {
                    // A bare `bump` is the canonical one Anchor derives.
                    continue;
                };

                // The hazard is specifically caller-supplied data. A value read
                // from an account is the program's own stored bump.
                let Some(argument) = arguments
                    .iter()
                    .find(|argument| mentions_argument(value, argument))
                else {
                    continue;
                };

                findings.push(ctx.finding(
                    &METADATA,
                    bump.location,
                    &field.item_path,
                    format!(
                        "`{}.{}` derives its address with `bump = {}`, which comes from the \
                         instruction argument `{}`. The caller chooses the bump, so they can \
                         derive several valid addresses for the same seeds. Use a bare `bump` \
                         and let Anchor supply the canonical one.",
                        accounts.name, field.name, value, argument
                    ),
                ));
            }
        }

        findings
    }
}

/// The argument names declared by `#[instruction(...)]`.
///
/// Anchor requires this attribute before instruction data can be referenced in
/// constraints, so it is a complete list of what the caller controls here.
fn instruction_arguments(accounts: &AccountsStruct) -> Vec<String> {
    let Some(args) = &accounts.instruction_args else {
        return Vec::new();
    };

    args.split(',')
        .filter_map(|argument| {
            let name = argument.split(':').next()?.trim();
            (!name.is_empty()).then(|| name.to_string())
        })
        .collect()
}

/// Whether a bump expression reads the named instruction argument.
///
/// Matched on a word boundary so that an argument called `bump` does not match
/// `market.bump`, which is the stored-bump idiom and the whole point of the
/// distinction.
fn mentions_argument(expression: &str, argument: &str) -> bool {
    expression.match_indices(argument).any(|(start, matched)| {
        let before = expression[..start].chars().next_back();
        let after = expression[start + matched.len()..].chars().next();
        let is_edge = |ch: Option<char>| ch.is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_');
        // A leading `.` means this is a field of something else, not the
        // argument itself: `market.bump` is storage, `bump` is instruction data.
        is_edge(before) && before != Some('.') && is_edge(after)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instruction_data_is_distinguished_from_stored_state() {
        assert!(mentions_argument("market_bump", "market_bump"));
        assert!(mentions_argument("bump", "bump"));
        assert!(mentions_argument("args.bump", "args"));

        // The stored-bump idiom, which must never match.
        assert!(!mentions_argument("market.bump", "bump"));
        assert!(!mentions_argument("offer.bump", "bump"));
        assert!(!mentions_argument("ctx.bumps.market", "bump"));
        // Nor a longer identifier that merely contains the argument name.
        assert!(!mentions_argument("bump_seed_store", "bump"));
    }
}
