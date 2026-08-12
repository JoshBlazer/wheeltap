//! WT007 — Arbitrary CPI target.
//!
//! A cross-program invocation carries the invoking program's authority with it.
//! If the callee's address comes from an account the caller supplied and nothing
//! pinned, the caller chooses who receives that authority — including their own
//! program, which can then do whatever the signing PDA is permitted to do.
//!
//! `Program<'info, T>` and `Interface<'info, T>` exist to close this: both
//! assert the address before the handler runs.

use wheeltap_core::model::{AccountField, ProgramContext};
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

use crate::body;

pub struct ArbitraryCpi;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT007",
    name: "Arbitrary CPI target",
    severity: Severity::Critical,
    confidence: Confidence::High,
    description: "A cross-program invocation targets an account whose address is not pinned",
    remediation: "Declare the callee as `Program<'info, T>`, or `Interface<'info, T>` where \
                  several implementations are accepted. Where no Anchor type exists, pin the \
                  address with `#[account(address = expected::ID)]`.",
    references: &[
        "https://solana.com/developers/courses/program-security/arbitrary-cpi",
        "https://github.com/coral-xyz/sealevel-attacks",
    ],
};

impl Detector for ArbitraryCpi {
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

            for handler in ctx.handlers_for(&accounts.name) {
                let body = body::text(handler);

                for field in &candidates {
                    if !is_cpi_target(&body, &field.name) {
                        continue;
                    }

                    findings.push(ctx.finding(
                        &METADATA,
                        field.location,
                        &field.item_path,
                        format!(
                            "`{}.{}` is invoked as a program by `{}`, but its address is never \
                             established. The caller chooses which program receives the \
                             invocation, and any signing seeds this program supplies go with it.",
                            accounts.name, field.name, handler.name
                        ),
                    ));
                }
            }
        }

        findings
    }
}

/// Whether a field could be an unpinned callee.
///
/// `Program` and `Interface` are already address-checked by Anchor, so only the
/// unchecked types qualify, and only when no `address` constraint pins them.
fn is_candidate(field: &AccountField) -> bool {
    field.ty.is_unchecked() && !field.constraints.asserts_address()
}

/// Whether the body hands this account to a CPI as the program to call.
///
/// Anchor's `CpiContext` constructors take the program account first, so the
/// account appearing as that argument is the signal. Merely holding an
/// `AccountInfo` proves nothing — being *called* is what matters.
fn is_cpi_target(body: &str, field: &str) -> bool {
    const CPI_CONSTRUCTORS: &[&str] = &[
        "CpiContext::new(",
        "CpiContext::new_with_signer(",
        "CpiContext::new_with_signer_and_remaining_accounts(",
    ];

    let account = format!("accounts.{field}");

    let in_cpi_context = CPI_CONSTRUCTORS.iter().any(|constructor| {
        body.match_indices(constructor).any(|(at, matched)| {
            first_argument(&body[at + matched.len() - 1..])
                .is_some_and(|first| first.contains(&account))
        })
    });

    // The raw form, where a program is invoked without Anchor's wrapper.
    let in_raw_invoke = ["invoke(", "invoke_signed("].iter().any(|call| {
        body.match_indices(call).any(|(at, matched)| {
            body[at + matched.len()..]
                .split_once(')')
                .is_some_and(|(args, _)| args.contains(&account))
        })
    });

    in_cpi_context || in_raw_invoke
}

/// The first argument of a parenthesised list starting at `text`.
///
/// Bounded to the argument itself, so that a program account mentioned *later*
/// in the same call — as one of the CPI's accounts, which is ordinary — is not
/// mistaken for the callee.
fn first_argument(text: &str) -> Option<&str> {
    let mut depth = 0usize;
    for (index, ch) in text.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return Some(&text[1..index]);
                }
            }
            ',' if depth == 1 => return Some(&text[1..index]),
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_first_cpi_argument_is_the_callee() {
        let body = "CpiContext::new(ctx.accounts.target_program.to_account_info(), \
                    Transfer { authority: ctx.accounts.vault_authority.to_account_info() })";

        assert!(is_cpi_target(body, "target_program"));
        assert!(
            !is_cpi_target(body, "vault_authority"),
            "an account passed *to* the CPI is not the program being called"
        );
    }

    #[test]
    fn raw_invocations_count_too() {
        let body =
            "invoke_signed(&instruction, &[ctx.accounts.helper_program.to_account_info()], seeds)";
        assert!(is_cpi_target(body, "helper_program"));
    }

    #[test]
    fn merely_holding_an_account_is_not_a_call() {
        let body = "msg!(\"{}\", ctx.accounts.metadata_program.key());";
        assert!(!is_cpi_target(body, "metadata_program"));
    }
}
