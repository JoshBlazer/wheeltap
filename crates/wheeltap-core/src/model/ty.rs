//! Anchor account types, as they appear on `#[derive(Accounts)]` fields.
//!
//! The type of a field is the single most security-relevant fact about it,
//! because it decides what Anchor validates *for* you. `Account<'info, T>`
//! makes the runtime check the owning program and the discriminator before your
//! handler runs; `AccountInfo<'info>` checks nothing at all. Half the detectors
//! in the catalogue are, at heart, questions about this enum.

use serde::Serialize;

/// The Anchor wrapper a field is declared with.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AnchorType {
    /// `Signer<'info>` — Anchor asserts `is_signer`.
    Signer,
    /// `AccountInfo<'info>` — raw, unvalidated.
    AccountInfo,
    /// `UncheckedAccount<'info>` — raw, unvalidated, but named honestly.
    UncheckedAccount,
    /// `SystemAccount<'info>` — Anchor asserts the owner is the System Program.
    SystemAccount,
    /// `Account<'info, T>` — owner and discriminator checked, data deserialised.
    Account { inner: String },
    /// `InterfaceAccount<'info, T>` — as `Account`, across several owning programs.
    InterfaceAccount { inner: String },
    /// `AccountLoader<'info, T>` — zero-copy; owner and discriminator checked.
    AccountLoader { inner: String },
    /// `Program<'info, T>` — Anchor asserts the address and that it is executable.
    Program { inner: String },
    /// `Interface<'info, T>` — as `Program`, across several accepted addresses.
    Interface { inner: String },
    /// `Sysvar<'info, T>` — Anchor asserts the sysvar address.
    Sysvar { inner: String },
    /// Another `#[derive(Accounts)]` struct, composed into this one.
    Composite { name: String },
    /// Anything else: a reference, a tuple, `Vec<_>`, a type alias we cannot see through.
    Other,
}

/// A field's declared type, including the wrappers Anchor allows around it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct FieldType {
    pub anchor: AnchorType,
    /// Declared as `Box<...>`.
    pub boxed: bool,
    /// Declared as `Option<...>` — an optional account, which may be absent.
    pub optional: bool,
    /// The type as written, normalised for display.
    pub text: String,
}

impl FieldType {
    /// Whether Anchor performs **no** validation on this account.
    ///
    /// These are the types that hand the developer a raw account and trust them
    /// to check it: the starting point for the missing-signer, missing-owner,
    /// and sysvar-spoofing detectors.
    #[must_use]
    pub fn is_unchecked(&self) -> bool {
        matches!(
            self.anchor,
            AnchorType::AccountInfo | AnchorType::UncheckedAccount
        )
    }

    /// Whether Anchor verifies the account's owning program for us.
    #[must_use]
    pub fn is_owner_checked(&self) -> bool {
        matches!(
            self.anchor,
            AnchorType::Account { .. }
                | AnchorType::InterfaceAccount { .. }
                | AnchorType::AccountLoader { .. }
                | AnchorType::Program { .. }
                | AnchorType::Interface { .. }
                | AnchorType::Sysvar { .. }
                | AnchorType::SystemAccount
        )
    }

    /// Whether Anchor asserts this account signed the transaction.
    #[must_use]
    pub fn is_signer_checked(&self) -> bool {
        matches!(self.anchor, AnchorType::Signer)
    }

    /// The inner type name, for the wrappers that carry one.
    #[must_use]
    pub fn inner(&self) -> Option<&str> {
        match &self.anchor {
            AnchorType::Account { inner }
            | AnchorType::InterfaceAccount { inner }
            | AnchorType::AccountLoader { inner }
            | AnchorType::Program { inner }
            | AnchorType::Interface { inner }
            | AnchorType::Sysvar { inner } => Some(inner),
            AnchorType::Composite { name } => Some(name),
            _ => None,
        }
    }
}

/// Classify a field's type.
#[must_use]
pub fn classify(ty: &syn::Type) -> FieldType {
    let text = render(ty);
    let mut boxed = false;
    let mut optional = false;
    let mut current = ty;

    // Peel the wrappers Anchor permits. `Box<Account<'info, T>>` is routine in
    // real programs -- large account structs blow the stack otherwise -- and
    // `Option<T>` marks an optional account. Neither changes what is validated,
    // so neither may change how a detector sees the field.
    loop {
        match unwrap_generic(current, "Box") {
            Some(inner) => {
                boxed = true;
                current = inner;
                continue;
            }
            None => match unwrap_generic(current, "Option") {
                Some(inner) => {
                    optional = true;
                    current = inner;
                }
                None => break,
            },
        }
    }

    FieldType {
        anchor: classify_bare(current),
        boxed,
        optional,
        text,
    }
}

/// Classify a type with the `Box`/`Option` wrappers already removed.
fn classify_bare(ty: &syn::Type) -> AnchorType {
    let syn::Type::Path(path) = ty else {
        return AnchorType::Other;
    };
    let Some(segment) = path.path.segments.last() else {
        return AnchorType::Other;
    };

    let name = segment.ident.to_string();
    let inner = || first_type_argument(segment).map(|t| render(&t));

    match name.as_str() {
        "Signer" => AnchorType::Signer,
        "AccountInfo" => AnchorType::AccountInfo,
        "UncheckedAccount" => AnchorType::UncheckedAccount,
        "SystemAccount" => AnchorType::SystemAccount,
        "Account" => AnchorType::Account {
            inner: inner().unwrap_or_default(),
        },
        "InterfaceAccount" => AnchorType::InterfaceAccount {
            inner: inner().unwrap_or_default(),
        },
        "AccountLoader" | "Loader" => AnchorType::AccountLoader {
            inner: inner().unwrap_or_default(),
        },
        "Program" => AnchorType::Program {
            inner: inner().unwrap_or_default(),
        },
        "Interface" => AnchorType::Interface {
            inner: inner().unwrap_or_default(),
        },
        "Sysvar" => AnchorType::Sysvar {
            inner: inner().unwrap_or_default(),
        },
        // An unrecognised path with no type arguments is, in an Accounts
        // struct, almost always a composed Accounts struct. Whether one
        // actually exists by that name is resolved later, against the context.
        _ if first_type_argument(segment).is_none() => AnchorType::Composite { name },
        _ => AnchorType::Other,
    }
}

/// If `ty` is `Wrapper<Inner>` for the named wrapper, yield `Inner`.
fn unwrap_generic<'a>(ty: &'a syn::Type, wrapper: &str) -> Option<&'a syn::Type> {
    let syn::Type::Path(path) = ty else {
        return None;
    };
    let segment = path.path.segments.last()?;
    if segment.ident != wrapper {
        return None;
    }
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    args.args.iter().find_map(|arg| match arg {
        syn::GenericArgument::Type(inner) => Some(inner),
        _ => None,
    })
}

/// The first generic *type* argument, skipping lifetimes.
///
/// Anchor's wrappers put the lifetime first — `Account<'info, Vault>` — so the
/// type we want is never in a fixed position.
fn first_type_argument(segment: &syn::PathSegment) -> Option<syn::Type> {
    let syn::PathArguments::AngleBracketed(args) = &segment.arguments else {
        return None;
    };
    args.args.iter().find_map(|arg| match arg {
        syn::GenericArgument::Type(ty) => Some(ty.clone()),
        _ => None,
    })
}

/// Render a type as compact source text.
#[must_use]
pub fn render(ty: &syn::Type) -> String {
    render_stream(&quote::ToTokens::to_token_stream(ty))
}

/// Render a token stream as readable source text.
///
/// `TokenStream::to_string()` puts a space between every token —
/// `Account < 'info , Vault >`, `vault . owner` — which is unreadable in a
/// report. Rather than patch that string afterwards (which cannot tell `a != b`
/// from a negation, and gets it wrong), this walks the tokens and uses the
/// spacing information `proc-macro2` already carries: a `Punct` marked `Joint`
/// is glued to what follows, which is exactly how `::`, `==`, `!=`, and `&&`
/// are represented.
///
/// The remaining rules are presentational and deliberately simple. Perfect
/// spacing is not the goal — this text is for display and for snippets, and
/// finding identity normalises whitespace regardless.
#[must_use]
pub fn render_stream(stream: &proc_macro2::TokenStream) -> String {
    use proc_macro2::{Delimiter, Spacing, TokenTree};

    fn is_punct(token: Option<&TokenTree>, chars: &str) -> bool {
        matches!(token, Some(TokenTree::Punct(p)) if chars.contains(p.as_char()))
    }

    let mut out = String::new();
    let tokens: Vec<TokenTree> = stream.clone().into_iter().collect();

    for (i, token) in tokens.iter().enumerate() {
        let prev = i.checked_sub(1).and_then(|j| tokens.get(j));
        let before_prev = i.checked_sub(2).and_then(|j| tokens.get(j));

        let space = match (prev, token) {
            // Nothing precedes the first token.
            (None, _) => false,
            // A Joint punct is glued to the next token by construction.
            (Some(TokenTree::Punct(p)), _) if p.spacing() == Spacing::Joint => false,
            // Nothing takes a space before `.`, `:`, or the `?` operator.
            _ if is_punct(Some(token), ".:?") => false,
            // Field access closes up on both sides: `vault.owner`.
            _ if is_punct(prev, ".") => false,
            // A `::` closes up, but a lone `:` does not, so that a path reads
            // `MyError::Unauthorised` while a binding still reads `id: u64`.
            _ if is_punct(prev, ":") && is_punct(before_prev, ":") => false,
            // `**account.try_borrow_mut_lamports()?` — the double dereference
            // is ubiquitous in Solana code. A lone `*` still spaces, because
            // there is no way to tell a prefix deref from a multiplication.
            _ if is_punct(prev, "*")
                && (is_punct(Some(token), "*") || is_punct(before_prev, "*")) =>
            {
                false
            }
            // No space before a comma or semicolon; the space goes after.
            _ if is_punct(Some(token), ",;") => false,
            // Generic argument lists read as one unit: `Account<'info, Vault>`.
            _ if is_punct(prev, "<") || is_punct(Some(token), "<>") => false,
            // A call or index binds to what it follows: `key()`, `seeds[0]`.
            // After an operator it does not: `seeds = [b"vault"]`.
            (Some(TokenTree::Ident(_) | TokenTree::Group(_)), TokenTree::Group(g))
                if matches!(g.delimiter(), Delimiter::Parenthesis | Delimiter::Bracket) =>
            {
                false
            }
            _ => true,
        };

        if space {
            out.push(' ');
        }

        match token {
            TokenTree::Group(group) => {
                let (open, close) = match group.delimiter() {
                    Delimiter::Parenthesis => ("(", ")"),
                    Delimiter::Brace => ("{", "}"),
                    Delimiter::Bracket => ("[", "]"),
                    Delimiter::None => ("", ""),
                };
                out.push_str(open);
                out.push_str(&render_stream(&group.stream()));
                out.push_str(close);
            }
            other => out.push_str(&other.to_string()),
        }
    }

    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ty(text: &str) -> FieldType {
        classify(&syn::parse_str::<syn::Type>(text).expect("type must parse"))
    }

    #[test]
    fn recognises_every_anchor_account_type() {
        assert_eq!(ty("Signer<'info>").anchor, AnchorType::Signer);
        assert_eq!(ty("AccountInfo<'info>").anchor, AnchorType::AccountInfo);
        assert_eq!(
            ty("UncheckedAccount<'info>").anchor,
            AnchorType::UncheckedAccount
        );
        assert_eq!(ty("SystemAccount<'info>").anchor, AnchorType::SystemAccount);
        assert_eq!(
            ty("Account<'info, Vault>").anchor,
            AnchorType::Account {
                inner: "Vault".into()
            }
        );
        assert_eq!(
            ty("InterfaceAccount<'info, Mint>").anchor,
            AnchorType::InterfaceAccount {
                inner: "Mint".into()
            }
        );
        assert_eq!(
            ty("AccountLoader<'info, Book>").anchor,
            AnchorType::AccountLoader {
                inner: "Book".into()
            }
        );
        assert_eq!(
            ty("Program<'info, System>").anchor,
            AnchorType::Program {
                inner: "System".into()
            }
        );
        assert_eq!(
            ty("Interface<'info, TokenInterface>").anchor,
            AnchorType::Interface {
                inner: "TokenInterface".into()
            }
        );
        assert_eq!(
            ty("Sysvar<'info, Rent>").anchor,
            AnchorType::Sysvar {
                inner: "Rent".into()
            }
        );
    }

    /// Wrappers are presentation. A boxed account is validated exactly as an
    /// unboxed one, so a detector must not be able to tell them apart.
    #[test]
    fn sees_through_box_and_option_wrappers() {
        let boxed = ty("Box<Account<'info, Vault>>");
        assert_eq!(
            boxed.anchor,
            AnchorType::Account {
                inner: "Vault".into()
            }
        );
        assert!(boxed.boxed && !boxed.optional);

        let optional = ty("Option<Account<'info, Vault>>");
        assert!(optional.optional && !optional.boxed);

        let both = ty("Option<Box<Account<'info, Vault>>>");
        assert_eq!(
            both.anchor,
            AnchorType::Account {
                inner: "Vault".into()
            }
        );
        assert!(both.boxed && both.optional);
    }

    #[test]
    fn fully_qualified_paths_are_recognised() {
        assert_eq!(
            ty("anchor_lang::prelude::Signer<'info>").anchor,
            AnchorType::Signer
        );
    }

    #[test]
    fn unknown_plain_types_are_treated_as_composed_accounts_structs() {
        assert_eq!(
            ty("SharedAccounts<'info>").anchor,
            AnchorType::Composite {
                name: "SharedAccounts".into()
            }
        );
    }

    #[test]
    fn validation_questions_have_the_right_answers() {
        assert!(ty("AccountInfo<'info>").is_unchecked());
        assert!(ty("UncheckedAccount<'info>").is_unchecked());
        assert!(!ty("Account<'info, Vault>").is_unchecked());

        assert!(ty("Signer<'info>").is_signer_checked());
        assert!(!ty("AccountInfo<'info>").is_signer_checked());

        assert!(ty("Account<'info, Vault>").is_owner_checked());
        assert!(ty("Program<'info, System>").is_owner_checked());
        assert!(!ty("AccountInfo<'info>").is_owner_checked());
        assert!(
            !ty("UncheckedAccount<'info>").is_owner_checked(),
            "an honest name is not a check"
        );
    }

    #[test]
    fn rendered_text_is_readable() {
        assert_eq!(ty("Account<'info, Vault>").text, "Account<'info, Vault>");
        assert_eq!(
            ty("Box<Account<'info, Vault>>").text,
            "Box<Account<'info, Vault>>"
        );
    }
}
