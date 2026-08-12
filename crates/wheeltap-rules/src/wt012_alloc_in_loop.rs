//! WT012 — Allocation inside a loop.
//!
//! Compute units are a hard per-transaction budget, and heap allocation is
//! expensive relative to nearly everything else a program does. Cloning a
//! collection on every iteration turns a linear pass quadratic, and a program
//! that fits the budget in testing stops fitting it once an account grows.
//!
//! Hygiene rather than a vulnerability, hence Low — but a program that runs out
//! of compute is a program whose instruction cannot be executed, which for a
//! liquidation or a settlement is its own kind of security problem.

use syn::visit::Visit;
use wheeltap_core::model::ProgramContext;
use wheeltap_core::model::ty::render_stream;
use wheeltap_core::source::Location;
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

pub struct AllocInLoop;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT012",
    name: "Allocation in a loop",
    severity: Severity::Low,
    confidence: Confidence::Medium,
    description: "A collection is cloned or allocated on every iteration of a loop",
    remediation: "Hoist the allocation out of the loop, or borrow instead of cloning. Where \
                  the collection is only read, iterate over a reference.",
    references: &["https://solana.com/docs/core/fees#compute-budget"],
};

/// Calls that allocate. Deliberately short: `clone` on a `Pubkey` or an integer
/// is a copy, not an allocation, so the rule also requires the receiver to look
/// like a collection.
const ALLOCATING_CALLS: &[&str] = &["clone", "to_vec", "to_owned", "collect", "concat"];

impl Detector for AllocInLoop {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for handler in &ctx.handlers {
            let mut visitor = LoopVisitor {
                depth: 0,
                found: Vec::new(),
            };
            visitor.visit_block(&handler.item.block);

            for (text, span) in visitor.found {
                findings.push(ctx.finding(
                    &METADATA,
                    Location::from_span(handler.file, span),
                    &handler.item_path,
                    format!(
                        "`{}` in `{}` allocates on every iteration. Hoist it out of the loop, \
                         or borrow instead — compute units are a hard per-transaction budget.",
                        text.chars().take(60).collect::<String>(),
                        handler.name
                    ),
                ));
            }
        }

        findings
    }
}

struct LoopVisitor {
    depth: usize,
    found: Vec<(String, proc_macro2::Span)>,
}

impl LoopVisitor {
    fn enter_loop(&mut self, body: &syn::Block) {
        self.depth += 1;
        syn::visit::visit_block(self, body);
        self.depth -= 1;
    }
}

impl<'ast> Visit<'ast> for LoopVisitor {
    fn visit_expr_for_loop(&mut self, node: &'ast syn::ExprForLoop) {
        self.enter_loop(&node.body);
    }

    fn visit_expr_while(&mut self, node: &'ast syn::ExprWhile) {
        self.enter_loop(&node.body);
    }

    fn visit_expr_loop(&mut self, node: &'ast syn::ExprLoop) {
        self.enter_loop(&node.body);
    }

    fn visit_expr_method_call(&mut self, node: &'ast syn::ExprMethodCall) {
        if self.depth > 0 {
            let method = node.method.to_string();
            if ALLOCATING_CALLS.contains(&method.as_str()) {
                use quote::ToTokens as _;
                use syn::spanned::Spanned as _;
                let receiver = render_stream(&node.receiver.to_token_stream());

                // A `Pubkey` or an integer copied inside a loop is not an
                // allocation. Require the receiver to look like a collection.
                if looks_like_collection(&receiver) {
                    self.found
                        .push((render_stream(&node.to_token_stream()), node.span()));
                }
            }
        }
        syn::visit::visit_expr_method_call(self, node);
    }
}

/// Whether an expression looks like it holds a collection rather than a scalar.
///
/// Without types (ADR-001) this is a name heuristic, and it is the reason the
/// rule is medium confidence. It errs towards silence: a cloned collection with
/// an unhelpful name is missed rather than every `pubkey.clone()` reported.
fn looks_like_collection(receiver: &str) -> bool {
    const COLLECTION_WORDS: &[&str] = &[
        "vec",
        "list",
        "items",
        "entries",
        "accounts",
        "weights",
        "orders",
        "markets",
        "keys",
        "values",
        "data",
        "buffer",
        "bytes",
        "positions",
        "records",
        "nodes",
        "queue",
        "history",
    ];

    let lower = receiver.to_ascii_lowercase();
    COLLECTION_WORDS.iter().any(|word| lower.contains(word))
}
