//! WT013 — Unused account.
//!
//! An unchecked account declared in an instruction's account list that nothing
//! ever reads: no handler mentions it, and no constraint does either. The
//! interface says the instruction needs it; the code says otherwise.
//!
//! On its own this is rarely an exploit — Trail of Bits filed drift's instance,
//! TOB-DRIFT-18, as Informational. It earns a rule because of what it usually
//! means. An `AccountInfo` carries no validation of its own, so the only reason
//! to declare one is to check it by hand; an unused one with a `/// CHECK:`
//! comment is a check the author believed was there and is not.
//!
//! **Only unchecked accounts.** An unused `Signer` or `Account<T>` is reported
//! nowhere. Measured on drift, unused signers are almost all permissionless
//! cranks (`keeper: Signer`) where any signer is the design, and unused typed
//! accounts are mostly the global `state` passed by convention: 39 findings,
//! none of them a defect. Telling an intended crank from a forgotten authority
//! check is the question WT005 cannot answer either.
//!
//! **What counts as a use.** The account must be read as an account:
//! `ctx.accounts.admin`, a field of a destructured or aliased account list,
//! `self.admin` in a method on the Accounts struct, or a mention in another
//! field's constraint (`payer = admin`, `has_one = admin`, a seed). A local
//! variable that happens to share the name is not a use — that is exactly how
//! drift's `drift_signer` hides: the handler derives a local of the same name.
//!
//! **When the rule stays silent.** If any handler for the struct passes its
//! context or account list somewhere this analysis cannot follow — a helper
//! function, `to_account_infos()` — the struct is skipped. The use might be one
//! call away, and intraprocedural analysis (ADR-001) cannot know.

use std::collections::BTreeSet;

use proc_macro2::{Delimiter, Spacing, TokenStream, TokenTree};
use quote::ToTokens as _;
use wheeltap_core::model::constraints::ConstraintKind;
use wheeltap_core::model::{AccountField, AccountsStruct, ProgramContext};
use wheeltap_core::{Confidence, Detector, Finding, RuleMetadata, Severity};

pub struct UnusedAccount;

const METADATA: RuleMetadata = RuleMetadata {
    id: "WT013",
    name: "Unused account",
    severity: Severity::Medium,
    confidence: Confidence::Medium,
    description: "An unchecked account is declared for an instruction but never read by its handler or \
                  constraints",
    remediation: "Remove the account if the instruction does not need it. If it was meant to \
                  authorise or constrain the call, write that check: require it to sign, tie it \
                  to stored state with `has_one`, or compare its key in the handler.",
    references: &[
        "https://github.com/trailofbits/publications/blob/master/reviews/2023-02-driftv2-securityreview.pdf",
        "https://www.anchor-lang.com/docs/references/account-constraints",
    ],
};

impl Detector for UnusedAccount {
    fn rule_id(&self) -> &'static str {
        METADATA.id
    }

    fn metadata(&self) -> RuleMetadata {
        METADATA
    }

    fn check(&self, ctx: &ProgramContext) -> Vec<Finding> {
        let mut findings = Vec::new();

        for accounts in &ctx.accounts {
            let Some(used) = uses(ctx, accounts) else {
                continue;
            };
            let referenced = referenced_by_constraints(accounts);

            for field in &accounts.fields {
                if used.contains(&field.name)
                    || referenced.contains(&field.name)
                    || is_exempt(field, accounts)
                {
                    continue;
                }
                findings.push(ctx.finding(
                    &METADATA,
                    field.location,
                    &field.item_path,
                    message(accounts, field),
                ));
            }
        }

        findings
    }
}

fn message(accounts: &AccountsStruct, field: &AccountField) -> String {
    let lead = format!(
        "`{}.{}` is an unchecked account that is never used: no handler reads it and no \
         constraint mentions it.",
        accounts.name, field.name
    );
    match &field.check_comment {
        Some(comment) if !comment.is_empty() => format!(
            "{lead} Its `CHECK` comment says \"{comment}\", but no code performs that check. \
             Whatever this account was meant to establish, the instruction never asks it to."
        ),
        _ => format!(
            "{lead} Whatever this account was meant to establish, the instruction never asks it \
             to, and callers reading the interface will assume it does."
        ),
    }
}

/// Accounts this rule does not report even when nothing names them.
fn is_exempt(field: &AccountField, accounts: &AccountsStruct) -> bool {
    // Typed accounts validate themselves, and an unused one costs a slot in
    // the transaction rather than a check. See the module documentation.
    if !field.ty.is_unchecked() {
        return true;
    }

    let constraints = &field.constraints;

    // Anchor acts on these accounts before or after the handler runs: it
    // creates, zeroes, closes, or resizes them. That is a use.
    if constraints.any(|k| {
        matches!(
            k,
            ConstraintKind::Init
                | ConstraintKind::InitIfNeeded
                | ConstraintKind::Zero
                | ConstraintKind::Close { .. }
                | ConstraintKind::Realloc { .. }
        )
    }) {
        return true;
    }

    // A signer pinned to a fixed address is a complete gate on its own.
    if (field.ty.is_signer_checked() || constraints.asserts_signer())
        && constraints.asserts_address()
    {
        return true;
    }

    // An account whose own constraints relate it to another account is doing
    // the checking: `has_one = authority`, or seeds built from another key.
    // Likewise an explicit `constraint =` that names the account itself.
    constraints.iter().any(|c| {
        let explicit = matches!(c.kind, ConstraintKind::Custom { .. });
        value_of(&c.kind).is_some_and(|value| {
            root_idents(value).any(|ident| {
                (ident != field.name && accounts.field(ident).is_some())
                    || (explicit && ident == field.name)
            })
        })
    })
}

/// Names of fields mentioned in *another* field's constraint values.
fn referenced_by_constraints(accounts: &AccountsStruct) -> BTreeSet<String> {
    let mut referenced = BTreeSet::new();
    for field in &accounts.fields {
        for constraint in field.constraints.iter() {
            let Some(value) = value_of(&constraint.kind) else {
                continue;
            };
            for ident in root_idents(value) {
                if ident != field.name {
                    referenced.insert(ident.to_string());
                }
            }
        }
    }
    referenced
}

/// The value side of a constraint, where account names can appear.
fn value_of(kind: &ConstraintKind) -> Option<&str> {
    match kind {
        ConstraintKind::Seeds { raw }
        | ConstraintKind::SeedsProgram { raw }
        | ConstraintKind::Space { raw }
        | ConstraintKind::Owner { raw }
        | ConstraintKind::Address { raw }
        | ConstraintKind::Realloc { raw, .. } => Some(raw),
        ConstraintKind::HasOne { target, .. } => Some(target),
        ConstraintKind::Custom { expr, .. } => Some(expr),
        ConstraintKind::Close { destination } => Some(destination),
        ConstraintKind::Payer { payer } => Some(payer),
        ConstraintKind::Bump { value }
        | ConstraintKind::Namespaced { value, .. }
        | ConstraintKind::Other { value, .. } => value.as_deref(),
        ConstraintKind::Mut
        | ConstraintKind::Init
        | ConstraintKind::InitIfNeeded
        | ConstraintKind::Zero
        | ConstraintKind::Signer => None,
    }
}

/// Identifiers in an expression that stand on their own: not a field after
/// `.`, not a path segment before or after `::`, not a macro name.
///
/// In `config.admin == authority.key()` those are `config` and `authority` —
/// the accounts the expression reads. `admin` is a field of `config` and says
/// nothing about an account of that name.
fn root_idents(text: &str) -> impl Iterator<Item = &str> {
    let bytes = text.as_bytes();
    let mut found = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if c.is_ascii_alphabetic() || c == b'_' {
            let start = i;
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
            let before = text[..start].trim_end();
            let after = text[i..].trim_start();
            let is_member = before.ends_with('.') && !before.ends_with("..");
            let is_path = before.ends_with("::") || after.starts_with("::");
            let is_macro = after.starts_with('!') && !after.starts_with("!=");
            // A byte-string or raw-string prefix, `b"seed"`, is not a name.
            let is_prefix = after.starts_with('"');
            if !(is_member || is_path || is_macro || is_prefix) {
                found.push(&text[start..i]);
            }
        } else if c.is_ascii_digit() {
            // Skip numeric literals whole, suffix included: `10u64`.
            while i < bytes.len() && (bytes[i].is_ascii_alphanumeric() || bytes[i] == b'_') {
                i += 1;
            }
        } else if c == b'"' {
            // Skip string contents.
            i += 1;
            while i < bytes.len() && bytes[i] != b'"' {
                i += if bytes[i] == b'\\' { 2 } else { 1 };
            }
            i += 1;
        } else {
            i += 1;
        }
    }
    found.into_iter()
}

/// Every field of `accounts` read as an account by its handlers or methods.
///
/// `None` when the account list escapes somewhere this analysis cannot follow,
/// or when no handler for the struct was found at all. Either way the honest
/// answer is "unknown", and unknown is never reported.
fn uses(ctx: &ProgramContext, accounts: &AccountsStruct) -> Option<BTreeSet<String>> {
    let handlers: Vec<_> = ctx.handlers_for(accounts).collect();
    if handlers.is_empty() {
        return None;
    }

    let fields: BTreeSet<&str> = accounts.fields.iter().map(|f| f.name.as_str()).collect();
    let methods: BTreeSet<String> = ctx
        .impls_for(accounts)
        .flat_map(|block| block.methods())
        .map(|m| m.sig.ident.to_string())
        .collect();
    let handler_names: BTreeSet<String> = handlers.iter().map(|h| h.name.clone()).collect();

    let scope = Scope {
        struct_name: &accounts.name,
        fields: &fields,
        methods: &methods,
        handler_names: &handler_names,
    };
    let mut used = BTreeSet::new();

    for handler in &handlers {
        let param = context_param(&handler.item.sig)?;
        let tokens = flatten(handler.item.block.to_token_stream());
        scope.read_context(&tokens, &param, &mut used)?;
    }

    // A handler that reads no accounts at all leaves the instruction to its
    // constraints, the shape of Anchor's own constraint tests. There is no use
    // to compare a missing one against.
    if used.is_empty() && ctx.impls_for(accounts).next().is_none() {
        return None;
    }

    for block in ctx.impls_for(accounts) {
        for method in block.methods() {
            let tokens = flatten(method.block.to_token_stream());
            scope.read_receiver(&tokens, "self", &mut used)?;
        }
    }

    Some(used)
}

/// The name a handler gives its `Context` parameter, if it is a plain binding.
fn context_param(sig: &syn::Signature) -> Option<String> {
    let syn::FnArg::Typed(arg) = sig.inputs.first()? else {
        return None;
    };
    match &*arg.pat {
        syn::Pat::Ident(ident) => Some(ident.ident.to_string()),
        _ => None,
    }
}

/// One token, with groups flattened into open and close markers so that a
/// pattern spanning a bracket can be matched by position.
#[derive(Debug, Clone, PartialEq, Eq)]
enum Tok {
    Ident(String),
    Punct(char, Spacing),
    Open(Delimiter),
    Close(Delimiter),
    Literal,
}

fn flatten(stream: TokenStream) -> Vec<Tok> {
    let mut out = Vec::new();
    flatten_into(stream, &mut out);
    out
}

fn flatten_into(stream: TokenStream, out: &mut Vec<Tok>) {
    for token in stream {
        match token {
            TokenTree::Ident(ident) => out.push(Tok::Ident(ident.to_string())),
            TokenTree::Punct(punct) => out.push(Tok::Punct(punct.as_char(), punct.spacing())),
            TokenTree::Literal(_) => out.push(Tok::Literal),
            TokenTree::Group(group) => {
                out.push(Tok::Open(group.delimiter()));
                flatten_into(group.stream(), out);
                out.push(Tok::Close(group.delimiter()));
            }
        }
    }
}

fn is_ident(tok: Option<&Tok>, name: &str) -> bool {
    matches!(tok, Some(Tok::Ident(i)) if i == name)
}

fn is_punct(tok: Option<&Tok>, ch: char) -> bool {
    matches!(tok, Some(Tok::Punct(c, _)) if *c == ch)
}

/// Whether `tokens[at]` is a free-standing `=`, not part of `==`, `<=`, `+=`.
fn is_assign(tokens: &[Tok], at: usize) -> bool {
    let alone = matches!(tokens.get(at), Some(Tok::Punct('=', Spacing::Alone)));
    let glued_to_previous = at
        .checked_sub(1)
        .is_some_and(|p| matches!(tokens.get(p), Some(Tok::Punct(_, Spacing::Joint))));
    alone && !glued_to_previous
}

/// Step back from `at` over `&`, `mut`, and `*`, returning the index before them.
fn skip_back_over_borrows(tokens: &[Tok], mut at: usize) -> Option<usize> {
    loop {
        at = at.checked_sub(1)?;
        match &tokens[at] {
            Tok::Punct('&' | '*', _) => {}
            Tok::Ident(i) if i == "mut" => {}
            _ => return Some(at),
        }
    }
}

/// What the analysis knows about one Accounts struct.
struct Scope<'a> {
    struct_name: &'a str,
    fields: &'a BTreeSet<&'a str>,
    methods: &'a BTreeSet<String>,
    handler_names: &'a BTreeSet<String>,
}

impl Scope<'_> {
    /// Read a handler body through its context parameter. `None` if the
    /// account list escapes.
    fn read_context(&self, tokens: &[Tok], param: &str, used: &mut BTreeSet<String>) -> Option<()> {
        let mut aliases = Vec::new();

        for at in 0..tokens.len() {
            if !is_ident(tokens.get(at), param)
                || is_punct(at.checked_sub(1).map(|p| &tokens[p]), '.')
            {
                continue;
            }

            if !is_punct(tokens.get(at + 1), '.') {
                // The context itself is handed somewhere: fine only when it is
                // another handler for the same accounts, which is read anyway.
                self.delegates_to_handler(tokens, at).then_some(())?;
                continue;
            }

            if !is_ident(tokens.get(at + 2), "accounts") {
                // `ctx.bumps`, `ctx.program_id`, `ctx.remaining_accounts`.
                continue;
            }

            let after = at + 3;
            if is_punct(tokens.get(after), '.') {
                self.read_member(tokens.get(after + 1), used)?;
            } else {
                // `ctx.accounts` taken whole: an alias or a destructuring.
                if let Some(alias) = self.binding(tokens, at, used)? {
                    aliases.push(alias);
                }
            }
        }

        for alias in aliases {
            self.read_receiver(tokens, &alias, used)?;
        }
        Some(())
    }

    /// Read uses through a name that stands for the whole account list:
    /// `self` in a method, or a local alias. `None` if it escapes.
    fn read_receiver(&self, tokens: &[Tok], name: &str, used: &mut BTreeSet<String>) -> Option<()> {
        for at in 0..tokens.len() {
            if !is_ident(tokens.get(at), name)
                || is_punct(at.checked_sub(1).map(|p| &tokens[p]), '.')
            {
                continue;
            }
            if is_punct(tokens.get(at + 1), '.') {
                self.read_member(tokens.get(at + 2), used)?;
            } else if is_assign(tokens, at + 1) || is_punct(tokens.get(at + 1), ':') {
                // The binding site itself, `let accounts = ...`.
            } else {
                return None;
            }
        }
        Some(())
    }

    /// `<accounts>.<member>`: a field is a use, a method on the struct is fine,
    /// and anything else — `to_account_infos()` — takes every account at once.
    fn read_member(&self, member: Option<&Tok>, used: &mut BTreeSet<String>) -> Option<()> {
        let Some(Tok::Ident(member)) = member else {
            return None;
        };
        if self.fields.contains(member.as_str()) {
            used.insert(member.clone());
            Some(())
        } else if self.methods.contains(member) {
            Some(())
        } else {
            None
        }
    }

    /// `ctx` passed as the first argument of a call to another handler.
    fn delegates_to_handler(&self, tokens: &[Tok], at: usize) -> bool {
        let Some(open) = skip_back_over_borrows(tokens, at) else {
            return false;
        };
        if tokens[open] != Tok::Open(Delimiter::Parenthesis) {
            return false;
        }
        matches!(
            open.checked_sub(1).map(|p| &tokens[p]),
            Some(Tok::Ident(callee)) if self.handler_names.contains(callee)
        )
    }

    /// Classify `<pattern> = [&mut] ctx.accounts`.
    ///
    /// `Some(Some(alias))` for `let accounts = &mut ctx.accounts`;
    /// `Some(None)` for `let Swap { a, b, .. } = ctx.accounts`, whose named
    /// fields are recorded as used; `None` for anything else, which escapes.
    fn binding(
        &self,
        tokens: &[Tok],
        at: usize,
        used: &mut BTreeSet<String>,
    ) -> Option<Option<String>> {
        let eq = skip_back_over_borrows(tokens, at)?;
        if !is_assign(tokens, eq) {
            return None;
        }
        let before = eq.checked_sub(1)?;
        match &tokens[before] {
            Tok::Ident(alias) if alias != "mut" => Some(Some(alias.clone())),
            Tok::Close(Delimiter::Brace) => {
                let open = matching_open(tokens, before)?;
                if !is_ident(open.checked_sub(1).map(|p| &tokens[p]), self.struct_name) {
                    return None;
                }
                for tok in &tokens[open + 1..before] {
                    if let Tok::Ident(name) = tok
                        && self.fields.contains(name.as_str())
                    {
                        used.insert(name.clone());
                    }
                }
                Some(None)
            }
            _ => None,
        }
    }
}

/// Index of the `Open` matching the `Close` at `close`.
fn matching_open(tokens: &[Tok], close: usize) -> Option<usize> {
    let mut depth = 0usize;
    for at in (0..=close).rev() {
        match tokens[at] {
            Tok::Close(_) => depth += 1,
            Tok::Open(_) => {
                depth -= 1;
                if depth == 0 {
                    return Some(at);
                }
            }
            _ => {}
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn roots(text: &str) -> Vec<&str> {
        root_idents(text).collect()
    }

    #[test]
    fn root_identifiers_skip_members_paths_and_macros() {
        assert_eq!(
            roots("config.admin == authority.key()"),
            ["config", "authority"]
        );
        assert_eq!(roots("[b\"pool\", config.key().as_ref()]"), ["config"]);
        assert_eq!(roots("State::SIZE + 8"), Vec::<&str>::new());
        assert_eq!(roots("require!(x)"), ["x"]);
        assert_eq!(roots("10u64"), Vec::<&str>::new());
    }

    fn scan(source: &str) -> Vec<String> {
        let dir = tempfile::TempDir::new().expect("tempdir");
        std::fs::write(dir.path().join("lib.rs"), source).expect("write");
        let ctx = ProgramContext::scan(dir.path());
        UnusedAccount
            .check(&ctx)
            .into_iter()
            .map(|f| f.item_path)
            .collect()
    }

    #[test]
    fn a_local_with_the_same_name_is_not_a_use() {
        let found = scan(
            "pub fn go(ctx: Context<A>) -> Result<()> {
                let hidden = 1;
                ctx.accounts.seen.x = hidden;
                Ok(())
            }
            #[derive(Accounts)]
            pub struct A<'info> {
                #[account(mut)] pub seen: Account<'info, S>,
                /// CHECK: unused
                pub hidden: AccountInfo<'info>,
            }",
        );
        assert_eq!(found, ["A.hidden"]);
    }

    #[test]
    fn an_account_list_passed_to_a_helper_is_not_judged() {
        let found = scan(
            "pub fn go(ctx: Context<A>) -> Result<()> { helper(ctx) }
            #[derive(Accounts)]
            pub struct A<'info> { /// CHECK: x
                pub hidden: AccountInfo<'info> }",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn to_account_infos_uses_everything() {
        let found = scan(
            "pub fn go(ctx: Context<A>) -> Result<()> {
                let infos = ctx.accounts.to_account_infos();
                Ok(())
            }
            #[derive(Accounts)]
            pub struct A<'info> { /// CHECK: x
                pub hidden: AccountInfo<'info> }",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn a_struct_with_no_handler_is_not_judged() {
        let found = scan(
            "#[derive(Accounts)]
            pub struct A<'info> { /// CHECK: x
                pub hidden: AccountInfo<'info> }",
        );
        assert!(found.is_empty(), "{found:?}");
    }

    #[test]
    fn uses_inside_macros_count() {
        let found = scan(
            "pub fn go(ctx: Context<A>) -> Result<()> {
                msg!(\"{}\", ctx.accounts.logged.key());
                Ok(())
            }
            #[derive(Accounts)]
            pub struct A<'info> { /// CHECK: x
                pub logged: AccountInfo<'info> }",
        );
        assert!(found.is_empty(), "{found:?}");
    }
}
