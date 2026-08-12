//! Reading handler bodies.
//!
//! Detectors that ask "does this function validate the account before using
//! it?" need the function, not just the account list. This module provides the
//! two things they need: a rendered form of a body for substring questions, and
//! an arithmetic walker.
//!
//! Everything here is **intraprocedural** — one function, no calls followed.
//! That is the boundary set by ADR-001, and it is why rules built on it report
//! `confidence: medium`.

use syn::visit::Visit;
use wheeltap_core::model::Handler;
use wheeltap_core::model::ty::render_stream;

/// Method names that read an account's raw bytes.
///
/// Reading the bytes is the moment an unvalidated account becomes trusted
/// state, which is what makes it the trigger for the owner-check rule.
const READ_METHODS: &[&str] = &[
    "try_borrow_data",
    "try_borrow_mut_data",
    "try_from_slice",
    "try_deserialize",
    "try_deserialize_unchecked",
    "deserialize",
    "try_from",
];

// `load`, `load_mut`, and `load_init` are deliberately absent. They are
// `AccountLoader`'s own API, which verifies the owner and discriminator before
// handing back data -- and on a bare `AccountInfo` no such method exists, so any
// `load` we see belongs to a typed wrapper that must do its own checking to
// compile at all. Including them produced eighteen findings on drift, every one
// of them a zero-copy loader doing exactly the right thing.

/// A handler body rendered as compact source text.
///
/// Substring matching over this is deliberate rather than lazy. It sees inside
/// macro invocations — `require_keys_eq!(*ctx.accounts.entry.owner, ..)` is a
/// token stream that no expression visitor will walk into, and missing it would
/// report correct code as a critical vulnerability.
#[must_use]
pub fn text(handler: &Handler) -> String {
    render_stream(&quote_block(&handler.item.block))
}

fn quote_block(block: &syn::Block) -> proc_macro2::TokenStream {
    use quote::ToTokens as _;
    block.to_token_stream()
}

/// Whether the body reads the raw data of `ctx.accounts.<field>`.
#[must_use]
pub fn reads_account_data(body: &str, field: &str) -> bool {
    let receiver = format!("accounts.{field}");

    READ_METHODS.iter().any(|method| {
        // `ctx.accounts.oracle.try_borrow_data()`
        body.contains(&format!("{receiver}.{method}"))
            // `Feed::try_from_slice(&ctx.accounts.oracle.data.borrow())`, or
            // `Account::try_from(&ctx.accounts.oracle)`.
            || body
                .match_indices(&format!("{method}("))
                .any(|(at, _)| argument_list_mentions(body, at + method.len(), &receiver))
    }) || body.contains(&format!("{receiver}.data"))
}

/// Whether the parenthesised list beginning at `open` mentions `needle`.
///
/// Bounded to the matching close paren so that a read of one account is not
/// credited to another mentioned later in the function.
fn argument_list_mentions(body: &str, open: usize, needle: &str) -> bool {
    let rest = &body[open..];
    let mut depth = 0usize;
    for (index, ch) in rest.char_indices() {
        match ch {
            '(' => depth += 1,
            ')' => {
                depth -= 1;
                if depth == 0 {
                    return rest[..index].contains(needle);
                }
            }
            _ => {}
        }
    }
    false
}

/// Whether the body asserts the owning program of `ctx.accounts.<field>`.
///
/// Permissive by design: any mention of the account's `.owner` counts as an
/// assertion. Over-suppressing costs a missed finding; under-suppressing calls
/// correct code a critical vulnerability, and only one of those gets the tool
/// uninstalled.
#[must_use]
pub fn asserts_owner(body: &str, field: &str) -> bool {
    body.contains(&format!("accounts.{field}.owner"))
        || body.contains(&format!("{field}.owner"))
        || body.contains(&format!("{field}.to_account_info().owner"))
}

/// An arithmetic operation found in a body.
#[derive(Debug, Clone)]
pub struct Arithmetic {
    /// The operator as written, e.g. `+` or `-=`.
    pub operator: &'static str,
    /// The whole expression, rendered.
    pub text: String,
    pub span: proc_macro2::Span,
}

/// Collect `+`, `-`, `*` and their compound-assignment forms from a body.
///
/// Division is excluded: it cannot overflow in the wrapping sense, and its
/// hazard is a different one (truncation and division by zero) that deserves
/// its own rule rather than being folded in here.
#[must_use]
pub fn arithmetic(handler: &Handler) -> Vec<Arithmetic> {
    let mut visitor = ArithmeticVisitor { found: Vec::new() };
    visitor.visit_block(&handler.item.block);
    visitor.found
}

struct ArithmeticVisitor {
    found: Vec<Arithmetic>,
}

impl<'ast> Visit<'ast> for ArithmeticVisitor {
    fn visit_expr_binary(&mut self, node: &'ast syn::ExprBinary) {
        use syn::BinOp;

        let operator = match node.op {
            BinOp::Add(_) => Some("+"),
            BinOp::Sub(_) => Some("-"),
            BinOp::Mul(_) => Some("*"),
            BinOp::AddAssign(_) => Some("+="),
            BinOp::SubAssign(_) => Some("-="),
            BinOp::MulAssign(_) => Some("*="),
            _ => None,
        };

        if let Some(operator) = operator {
            use quote::ToTokens as _;
            use syn::spanned::Spanned as _;
            self.found.push(Arithmetic {
                operator,
                text: render_stream(&node.to_token_stream()),
                span: node.span(),
            });
        }

        // Keep walking: `a + b * c` holds two operations, and a nested one may
        // be the dangerous half.
        syn::visit::visit_expr_binary(self, node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handler_from(source: &str) -> Handler {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("lib.rs"), source).expect("write");
        let ctx = wheeltap_core::ProgramContext::scan(dir.path());
        ctx.handlers.into_iter().next().expect("one handler")
    }

    #[test]
    fn finds_arithmetic_including_nested_and_compound() {
        let handler = handler_from(
            "pub fn go(ctx: Context<A>) -> Result<()> {
                let a = x + y * z;
                s.total += a;
                let ok = p.checked_add(q);
                Ok(())
            }",
        );

        let found = arithmetic(&handler);
        let operators: Vec<_> = found.iter().map(|a| a.operator).collect();
        assert!(operators.contains(&"+"));
        assert!(operators.contains(&"*"), "nested operation is not skipped");
        assert!(operators.contains(&"+="));
        assert_eq!(found.len(), 3, "checked_add is a call, not an operator");
    }

    #[test]
    fn recognises_data_reads_through_several_spellings() {
        let handler = handler_from(
            "pub fn go(ctx: Context<A>) -> Result<()> {
                let d = ctx.accounts.oracle.try_borrow_data()?;
                let f = Feed::try_from_slice(&ctx.accounts.feed.data.borrow())?;
                Ok(())
            }",
        );
        let body = text(&handler);

        assert!(reads_account_data(&body, "oracle"));
        assert!(reads_account_data(&body, "feed"));
        assert!(!reads_account_data(&body, "elsewhere"));
    }

    /// An account handed to a CPI is not a data read, and treating it as one
    /// would flag most real Anchor programs.
    #[test]
    fn passing_an_account_to_a_cpi_is_not_a_data_read() {
        let handler = handler_from(
            "pub fn go(ctx: Context<A>) -> Result<()> {
                let accounts = Transfer {
                    from: ctx.accounts.source.to_account_info(),
                    authority: ctx.accounts.authority.to_account_info(),
                };
                token::transfer(CpiContext::new(ctx.accounts.token_program.to_account_info(), accounts), 1)
            }",
        );
        let body = text(&handler);

        assert!(!reads_account_data(&body, "source"));
        assert!(!reads_account_data(&body, "authority"));
        assert!(!reads_account_data(&body, "token_program"));
    }

    /// Owner assertions frequently live inside macros, which no expression
    /// visitor walks into.
    #[test]
    fn owner_assertions_inside_macros_are_seen() {
        let handler = handler_from(
            "pub fn go(ctx: Context<A>) -> Result<()> {
                require_keys_eq!(*ctx.accounts.entry.owner, expected, E::Wrong);
                Ok(())
            }",
        );
        assert!(asserts_owner(&text(&handler), "entry"));
    }

    #[test]
    fn owner_assertions_by_comparison_are_seen() {
        let handler = handler_from(
            "pub fn go(ctx: Context<A>) -> Result<()> {
                if ctx.accounts.entry.owner != &expected { return err!(E::Wrong); }
                Ok(())
            }",
        );
        assert!(asserts_owner(&text(&handler), "entry"));
        assert!(!asserts_owner(&text(&handler), "other"));
    }

    /// A read credited to the wrong account would be a false positive on one
    /// and a false negative on the other.
    #[test]
    fn a_read_is_not_credited_to_an_account_mentioned_later() {
        let handler = handler_from(
            "pub fn go(ctx: Context<A>) -> Result<()> {
                let f = Feed::try_from_slice(&raw)?;
                msg!(\"{}\", ctx.accounts.other.key());
                Ok(())
            }",
        );
        assert!(!reads_account_data(&text(&handler), "other"));
    }
}
