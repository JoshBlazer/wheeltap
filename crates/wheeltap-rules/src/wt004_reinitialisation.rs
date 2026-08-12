//! WT004 — Account reinitialisation.
//!
//! `init_if_needed` asks Anchor to create the account only if it does not exist,
//! and then runs the handler either way. The handler cannot tell the two cases
//! apart unless it asks, and a handler that does not ask will happily overwrite
//! live state belonging to someone else.
//!
//! The constraint is not a bug in itself — creating an associated token account
//! on demand is the idiomatic use of it, and appears in nearly every program
//! that moves tokens. What matters is *whose* state is at risk and whether the
//! handler checks.

use wheeltap_core::model::{AccountField, ProgramContext};
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

use crate::body;

pub struct Reinitialisation;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT004",
    name: "Account reinitialisation",
    severity: Severity::High,
    confidence: Confidence::Medium,
    description: "`init_if_needed` on program state, with no check for an already-live account",
    remediation: "Ask whether the account is already initialised before writing the fields \
                  that establish ownership — compare the stored authority against \
                  `Pubkey::default()`, or require it to match the caller. Where creation and \
                  update are genuinely different operations, give them separate instructions \
                  and use plain `init`.",
    references: &[
        "https://solana.com/developers/courses/program-security/reinitialization-attacks",
        "https://www.anchor-lang.com/docs/account-constraints",
    ],
};

impl Detector for Reinitialisation {
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
                if !is_program_state_init_if_needed(field, ctx) {
                    continue;
                }

                // A handler that checks before writing is doing the right thing.
                // Every handler using this account list must check, since any of
                // them could be the reinitialising one.
                let guarded = ctx
                    .handlers_for(&accounts.name)
                    .all(|handler| guards_initialisation(&body::text(handler), &field.name));
                if guarded {
                    continue;
                }

                findings.push(ctx.finding(
                    &METADATA,
                    field.location,
                    &field.item_path,
                    format!(
                        "`{}.{}` uses `init_if_needed` on program state, and no handler checks \
                         whether the account already holds data. A caller can pass an existing \
                         account and have the handler overwrite state that belongs to someone \
                         else.",
                        accounts.name, field.name
                    ),
                ));
            }
        }

        findings
    }
}

/// Whether a field creates-or-reuses one of *this program's* state accounts.
///
/// The inner type must be a struct the scan saw declared with `#[account]`.
/// That single condition excludes the entire idiomatic case: `TokenAccount` and
/// `Mint` belong to the token program, are not declared here, and their state is
/// not ours to clobber.
fn is_program_state_init_if_needed(field: &AccountField, ctx: &ProgramContext) -> bool {
    if !field.constraints.any(|k| {
        matches!(
            k,
            wheeltap_core::model::constraints::ConstraintKind::InitIfNeeded
        )
    }) {
        return false;
    }

    field
        .ty
        .inner()
        .is_some_and(|inner| ctx.state(inner).is_some())
}

/// Whether a handler body asks if the account is already live before writing.
///
/// Recognises the shapes real code uses: comparing a stored key against
/// `Pubkey::default()`, requiring the stored authority to match the caller, or
/// testing an explicit initialisation flag.
fn guards_initialisation(body: &str, field: &str) -> bool {
    let mentions_field = body.contains(field);
    if !mentions_field {
        // The handler never touches this account, so it cannot clobber it.
        return true;
    }

    const GUARDS: &[&str] = &[
        "Pubkey::default()",
        "is_initialized",
        "is_initialised",
        "require_keys_eq!",
        "require_eq!",
        "discriminator",
    ];

    GUARDS.iter().any(|guard| body.contains(guard))
}
