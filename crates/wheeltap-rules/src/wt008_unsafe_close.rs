//! WT008 — Unsafe account close.
//!
//! Draining an account's lamports is not closing it. The runtime reclaims an
//! account at the *end* of a transaction, and only if its balance is zero —
//! until then the data is intact and anyone can top the balance back up within
//! the same transaction. The account survives with all its state, which is the
//! revival attack.
//!
//! Anchor's `close = destination` constraint drains, zeroes, and reassigns.
//! Doing it by hand means doing all three.

use wheeltap_core::model::ProgramContext;
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

use crate::body;

pub struct UnsafeClose;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT008",
    name: "Unsafe account close",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "An account's lamports are zeroed without its data being cleared",
    remediation: "Prefer Anchor's `close = destination` constraint, which drains the lamports, \
                  zeroes the data, and assigns the account to the system program. Closing by \
                  hand requires all three — zeroing the balance alone leaves the account \
                  revivable within the same transaction.",
    references: &[
        "https://solana.com/developers/courses/program-security/closing-accounts",
        "https://www.anchor-lang.com/docs/account-constraints",
    ],
};

impl Detector for UnsafeClose {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for handler in &ctx.handlers {
            let text = body::text(handler);

            if !zeroes_lamports(&text) || clears_data(&text) {
                continue;
            }

            // Anchor's own `close` constraint does the whole job, so an account
            // list that uses it is not closing anything by hand.
            let uses_close_constraint = handler
                .accounts_struct
                .as_deref()
                .and_then(|name| ctx.accounts_struct(name))
                .is_some_and(|accounts| {
                    accounts.fields.iter().any(|field| {
                        field.constraints.any(|kind| {
                            matches!(
                                kind,
                                wheeltap_core::model::constraints::ConstraintKind::Close { .. }
                            )
                        })
                    })
                });
            if uses_close_constraint {
                continue;
            }

            findings.push(ctx.finding(
                &METADATA,
                handler.location,
                &handler.item_path,
                format!(
                    "`{}` sets an account's lamports to zero without clearing its data. The \
                     runtime only reclaims the account at the end of the transaction, so a \
                     caller can send lamports back within the same transaction and keep the \
                     account, its data intact.",
                    handler.name
                ),
            ));
        }

        findings
    }
}

/// Whether the body sets an account's lamport balance to zero.
///
/// Zeroing is the close attempt. Subtracting a payment is not, which is the
/// distinction that keeps this rule off every program that pays anyone.
fn zeroes_lamports(body: &str) -> bool {
    [
        "try_borrow_mut_lamports()? = 0",
        "lamports.borrow_mut() = 0",
    ]
    .iter()
    .any(|form| body.contains(form))
}

/// Whether the body also clears the account, by any of the means that work.
fn clears_data(body: &str) -> bool {
    const CLEARERS: &[&str] = &[
        "assign(&",
        "assign(",
        "realloc(0",
        "sol_memset",
        "data.borrow_mut().fill(0)",
        "fill(0)",
        "close(",
        "CLOSED_ACCOUNT_DISCRIMINATOR",
    ];
    CLEARERS.iter().any(|clearer| body.contains(clearer))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zeroing_is_distinguished_from_paying() {
        assert!(zeroes_lamports(
            "**position.try_borrow_mut_lamports()? = 0;"
        ));
        assert!(!zeroes_lamports(
            "**treasury.try_borrow_mut_lamports()? -= amount;"
        ));
        assert!(!zeroes_lamports(
            "**recipient.try_borrow_mut_lamports()? += amount;"
        ));
    }

    #[test]
    fn a_proper_manual_close_is_recognised() {
        let done_properly = "**position.try_borrow_mut_lamports()? = 0; \
                             position.assign(&system_program::ID); position.realloc(0, false)?;";
        assert!(zeroes_lamports(done_properly));
        assert!(clears_data(done_properly));
    }
}
