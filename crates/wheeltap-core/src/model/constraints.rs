//! Parsing `#[account(...)]` into a structured form.
//!
//! Anchor's constraint grammar is not Rust attribute-meta syntax, so `syn`'s
//! `parse_nested_meta` cannot read it: `has_one = authority @ MyError::Bad` puts
//! an `@` where Rust expects an expression to end, and it fails outright. We
//! therefore split the attribute's token stream by hand.
//!
//! Splitting at the top level is simpler than it sounds, because a `syn`
//! token stream nests bracketed content inside a single `Group` token. A comma
//! inside `seeds = [b"vault", user.key()]` is *inside* that group, so iterating
//! the stream never sees it. Top level falls out of the representation.

use proc_macro2::{Spacing, TokenStream, TokenTree};
use serde::Serialize;

use crate::source::{FileId, Location};

/// One `#[account(...)]` constraint.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "constraint", rename_all = "snake_case")]
pub enum ConstraintKind {
    /// `mut` — the account is written to.
    Mut,
    /// `init` — created by this instruction.
    Init,
    /// `init_if_needed` — created only if absent. Requires care: the handler
    /// runs on both an empty and an already-populated account.
    InitIfNeeded,
    /// `zero` — must be zeroed and uninitialised.
    Zero,
    /// `signer` — the older spelling of a signature requirement.
    Signer,
    /// `seeds = [...]` — a program-derived address.
    Seeds { raw: String },
    /// `seeds::program = ...` — PDA derived against another program.
    SeedsProgram { raw: String },
    /// `bump` with no value is the canonical bump Anchor computes.
    /// `bump = expr` takes the bump from somewhere else, which is where
    /// non-canonical-bump vulnerabilities live.
    Bump { value: Option<String> },
    /// `has_one = target [@ error]` — asserts `self.target == target.key()`.
    HasOne {
        target: String,
        error: Option<String>,
    },
    /// `constraint = expr [@ error]` — an arbitrary assertion.
    Custom { expr: String, error: Option<String> },
    /// `close = destination` — drains and closes the account.
    Close { destination: String },
    /// `payer = account` — funds an `init`.
    Payer { payer: String },
    /// `space = expr` — allocation size for an `init`.
    Space { raw: String },
    /// `owner = expr` — asserts the owning program explicitly.
    Owner { raw: String },
    /// `address = expr` — asserts the account's address.
    Address { raw: String },
    /// `realloc = ...` and its `realloc::` siblings.
    Realloc { key: String, raw: String },
    /// Namespaced constraints: `token::mint`, `associated_token::authority`,
    /// `mint::decimals`, and so on.
    Namespaced {
        namespace: String,
        key: String,
        value: Option<String>,
    },
    /// Anything the grammar grows that we do not yet model. Retained verbatim
    /// rather than dropped, so a detector can still see it and an unknown
    /// constraint never silently reads as absent.
    Other { key: String, value: Option<String> },
}

/// A constraint together with where it was written.
#[derive(Debug, Clone)]
pub struct Constraint {
    pub kind: ConstraintKind,
    /// The constraint as written, for snippets and finding identity.
    pub raw: String,
    pub location: Location,
}

/// All constraints on one field, with the questions detectors ask.
#[derive(Debug, Clone, Default)]
pub struct Constraints {
    pub items: Vec<Constraint>,
}

impl Constraints {
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    #[must_use]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Constraint> {
        self.items.iter()
    }

    /// Whether any constraint matches a predicate on its kind.
    pub fn any(&self, f: impl Fn(&ConstraintKind) -> bool) -> bool {
        self.items.iter().any(|c| f(&c.kind))
    }

    /// Find the first constraint whose kind matches.
    pub fn find(&self, f: impl Fn(&ConstraintKind) -> bool) -> Option<&Constraint> {
        self.items.iter().find(|c| f(&c.kind))
    }

    #[must_use]
    pub fn is_mut(&self) -> bool {
        self.any(|k| matches!(k, ConstraintKind::Mut))
    }

    /// Whether this field is initialised here, by either spelling.
    #[must_use]
    pub fn is_init(&self) -> bool {
        self.any(|k| matches!(k, ConstraintKind::Init | ConstraintKind::InitIfNeeded))
    }

    /// Whether the account is a PDA — that is, it declares seeds.
    #[must_use]
    pub fn is_pda(&self) -> bool {
        self.any(|k| matches!(k, ConstraintKind::Seeds { .. }))
    }

    /// Whether a declared bump is the canonical one Anchor derives.
    ///
    /// `None` when no bump is declared at all. `Some(false)` means the bump came
    /// from somewhere else — user input, an account field — which is exactly the
    /// non-canonical bump hazard.
    #[must_use]
    pub fn bump_is_canonical(&self) -> Option<bool> {
        self.items.iter().find_map(|c| match &c.kind {
            ConstraintKind::Bump { value } => Some(value.is_none()),
            _ => None,
        })
    }

    /// Every `has_one` target declared on this field.
    #[must_use]
    pub fn has_one_targets(&self) -> Vec<&str> {
        self.items
            .iter()
            .filter_map(|c| match &c.kind {
                ConstraintKind::HasOne { target, .. } => Some(target.as_str()),
                _ => None,
            })
            .collect()
    }

    /// Whether the field asserts a signature, by constraint rather than by type.
    #[must_use]
    pub fn asserts_signer(&self) -> bool {
        self.any(|k| match k {
            ConstraintKind::Signer => true,
            // `constraint = authority.is_signer` and friends.
            ConstraintKind::Custom { expr, .. } => expr.contains("is_signer"),
            _ => false,
        })
    }

    /// Whether the field asserts an owning program, by `owner =` or by a
    /// custom constraint that mentions `.owner`.
    #[must_use]
    pub fn asserts_owner(&self) -> bool {
        self.any(|k| match k {
            ConstraintKind::Owner { .. } => true,
            ConstraintKind::Custom { expr, .. } => expr.contains(".owner"),
            _ => false,
        })
    }

    /// Whether the field pins the account's address, by `address =` or a
    /// custom constraint comparing `.key()`.
    #[must_use]
    pub fn asserts_address(&self) -> bool {
        self.any(|k| match k {
            ConstraintKind::Address { .. } => true,
            ConstraintKind::Custom { expr, .. } => expr.contains("key()") && expr.contains("=="),
            _ => false,
        })
    }
}

impl Serialize for Constraints {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeSeq;
        let mut seq = s.serialize_seq(Some(self.items.len()))?;
        for item in &self.items {
            seq.serialize_element(&item.raw)?;
        }
        seq.end()
    }
}

/// Parse every `#[account(...)]` attribute on a field.
///
/// Attributes other than `account` are ignored. A field may carry more than one
/// `#[account(...)]`; their constraints accumulate, as Anchor treats them.
#[must_use]
pub fn parse(attrs: &[syn::Attribute], file: FileId) -> Constraints {
    let mut items = Vec::new();
    for attr in attrs {
        if !attr.path().is_ident("account") {
            continue;
        }
        let syn::Meta::List(list) = &attr.meta else {
            // Bare `#[account]` — on a data struct, not a field. No constraints.
            continue;
        };
        for chunk in split(list.tokens.clone(), ',') {
            if let Some(constraint) = parse_one(&chunk, file) {
                items.push(constraint);
            }
        }
    }
    Constraints { items }
}

/// Parse one comma-separated constraint.
fn parse_one(tokens: &[TokenTree], file: FileId) -> Option<Constraint> {
    let first = tokens.first()?;
    let last = tokens.last()?;
    let location = Location {
        file,
        start: Location::from_span(file, first.span()).start,
        end: Location::from_span(file, last.span()).end,
    };
    let raw = render(tokens);

    // Split key from value at the first standalone `=`. Comparison operators
    // (`==`, `!=`, `>=`) are two-token sequences whose first token is Joint, so
    // they cannot be mistaken for the separator.
    let separator = tokens.iter().position(|t| is_punct(t, '=', Spacing::Alone));
    let (key_tokens, value_tokens) = match separator {
        Some(at) => (&tokens[..at], Some(&tokens[at + 1..])),
        None => (tokens, None),
    };

    let key = render(key_tokens);
    // `@ CustomError` after a value names the error to raise. Split it off so
    // that the value is the assertion alone.
    let (value, error) = match value_tokens {
        Some(value_tokens) => {
            let at = value_tokens
                .iter()
                .position(|t| is_punct(t, '@', Spacing::Alone));
            match at {
                Some(at) => (
                    Some(render(&value_tokens[..at])),
                    Some(render(&value_tokens[at + 1..])),
                ),
                None => (Some(render(value_tokens)), None),
            }
        }
        None => (None, None),
    };

    let kind = classify(&key, value, error);
    Some(Constraint {
        kind,
        raw,
        location,
    })
}

fn classify(key: &str, value: Option<String>, error: Option<String>) -> ConstraintKind {
    let owned = |v: Option<String>| v.unwrap_or_default();
    match key {
        "mut" => ConstraintKind::Mut,
        "init" => ConstraintKind::Init,
        "init_if_needed" => ConstraintKind::InitIfNeeded,
        "zero" => ConstraintKind::Zero,
        "signer" => ConstraintKind::Signer,
        "seeds" => ConstraintKind::Seeds { raw: owned(value) },
        "seeds::program" => ConstraintKind::SeedsProgram { raw: owned(value) },
        "bump" => ConstraintKind::Bump { value },
        "has_one" => ConstraintKind::HasOne {
            target: owned(value),
            error,
        },
        "constraint" => ConstraintKind::Custom {
            expr: owned(value),
            error,
        },
        "close" => ConstraintKind::Close {
            destination: owned(value),
        },
        "payer" => ConstraintKind::Payer {
            payer: owned(value),
        },
        "space" => ConstraintKind::Space { raw: owned(value) },
        "owner" => ConstraintKind::Owner { raw: owned(value) },
        "address" => ConstraintKind::Address { raw: owned(value) },
        _ if key == "realloc" || key.starts_with("realloc::") => ConstraintKind::Realloc {
            key: key.to_string(),
            raw: owned(value),
        },
        _ => match key.split_once("::") {
            Some((namespace, rest)) => ConstraintKind::Namespaced {
                namespace: namespace.to_string(),
                key: rest.to_string(),
                value,
            },
            None => ConstraintKind::Other {
                key: key.to_string(),
                value,
            },
        },
    }
}

/// Split a token stream on a top-level punctuation character.
fn split(tokens: TokenStream, separator: char) -> Vec<Vec<TokenTree>> {
    let mut chunks = Vec::new();
    let mut current = Vec::new();
    for token in tokens {
        if is_punct(&token, separator, Spacing::Alone) {
            if !current.is_empty() {
                chunks.push(std::mem::take(&mut current));
            }
        } else {
            current.push(token);
        }
    }
    if !current.is_empty() {
        chunks.push(current);
    }
    chunks
}

fn is_punct(token: &TokenTree, ch: char, spacing: Spacing) -> bool {
    matches!(token, TokenTree::Punct(p) if p.as_char() == ch && p.spacing() == spacing)
}

/// Render tokens back to compact source text.
fn render(tokens: &[TokenTree]) -> String {
    let stream: TokenStream = tokens.iter().cloned().collect();
    super::ty::render_stream(&stream)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `syn::Field` is not `Parse` on its own, so exercise attributes the way
    /// they actually appear: on a field of an Accounts struct.
    fn field_with(attrs: &str) -> syn::Field {
        let item: syn::ItemStruct = syn::parse_str(&format!(
            "struct Accounts<'info> {{ {attrs} pub authority: Signer<'info>, }}"
        ))
        .expect("struct must parse");
        item.fields.into_iter().next().expect("one field")
    }

    fn constraints(attr: &str) -> Constraints {
        parse(&field_with(attr).attrs, FileId(0))
    }

    fn kinds(attr: &str) -> Vec<ConstraintKind> {
        constraints(attr)
            .items
            .into_iter()
            .map(|c| c.kind)
            .collect()
    }

    #[test]
    fn parses_bare_flag_constraints() {
        assert_eq!(
            kinds("#[account(mut, init, zero, signer)]"),
            [
                ConstraintKind::Mut,
                ConstraintKind::Init,
                ConstraintKind::Zero,
                ConstraintKind::Signer
            ]
        );
        assert_eq!(
            kinds("#[account(init_if_needed)]"),
            [ConstraintKind::InitIfNeeded]
        );
    }

    /// The canonical-bump distinction, which a whole detector rests on.
    #[test]
    fn distinguishes_canonical_from_supplied_bumps() {
        assert_eq!(
            constraints("#[account(seeds = [b\"vault\"], bump)]").bump_is_canonical(),
            Some(true)
        );
        assert_eq!(
            constraints("#[account(seeds = [b\"vault\"], bump = args.bump)]").bump_is_canonical(),
            Some(false)
        );
        assert_eq!(
            constraints("#[account(mut)]").bump_is_canonical(),
            None,
            "no bump declared at all is distinct from a non-canonical one"
        );
    }

    /// Commas inside `seeds = [...]` are nested in a Group, so they must not
    /// split the constraint list.
    #[test]
    fn seeds_containing_commas_stay_one_constraint() {
        let parsed = constraints("#[account(seeds = [b\"vault\", user.key().as_ref()], bump)]");
        assert_eq!(parsed.len(), 2, "seeds and bump, not four constraints");
        assert!(parsed.is_pda());
        let seeds = parsed
            .find(|k| matches!(k, ConstraintKind::Seeds { .. }))
            .expect("seeds present");
        assert!(seeds.raw.contains("b\"vault\""));
        assert!(seeds.raw.contains("user.key()"));
    }

    #[test]
    fn has_one_carries_its_target_and_optional_error() {
        assert_eq!(
            kinds("#[account(has_one = authority)]"),
            [ConstraintKind::HasOne {
                target: "authority".into(),
                error: None
            }]
        );
        assert_eq!(
            kinds("#[account(has_one = authority @ EscrowError::Unauthorised)]"),
            [ConstraintKind::HasOne {
                target: "authority".into(),
                error: Some("EscrowError::Unauthorised".into())
            }]
        );
    }

    /// `==` must not be mistaken for the key/value separator.
    #[test]
    fn custom_constraints_keep_comparison_operators() {
        assert_eq!(
            kinds("#[account(constraint = vault.owner == authority.key())]"),
            [ConstraintKind::Custom {
                expr: "vault.owner == authority.key()".into(),
                error: None
            }]
        );
        assert_eq!(
            kinds("#[account(constraint = a != b @ MyError::Nope)]"),
            [ConstraintKind::Custom {
                expr: "a != b".into(),
                error: Some("MyError::Nope".into())
            }]
        );
    }

    #[test]
    fn parses_namespaced_constraints() {
        assert_eq!(
            kinds("#[account(token::mint = mint, token::authority = payer)]"),
            [
                ConstraintKind::Namespaced {
                    namespace: "token".into(),
                    key: "mint".into(),
                    value: Some("mint".into())
                },
                ConstraintKind::Namespaced {
                    namespace: "token".into(),
                    key: "authority".into(),
                    value: Some("payer".into())
                }
            ]
        );
    }

    #[test]
    fn parses_init_with_payer_and_space() {
        let parsed = constraints("#[account(init, payer = maker, space = 8 + Offer::INIT_SPACE)]");
        assert!(parsed.is_init());
        assert_eq!(
            parsed
                .find(|k| matches!(k, ConstraintKind::Space { .. }))
                .map(|c| c.raw.as_str()),
            Some("space = 8 + Offer::INIT_SPACE")
        );
    }

    /// Real programs wrap long constraint lists across lines.
    #[test]
    fn multi_line_attributes_parse_identically_to_one_line() {
        let across_lines = constraints(
            "#[account(
                init,
                payer = maker,
                seeds = [b\"offer\", maker.key().as_ref()],
                bump,
                has_one = maker
            )]",
        );
        assert_eq!(across_lines.len(), 5);
        assert!(across_lines.is_init() && across_lines.is_pda());
        assert_eq!(across_lines.has_one_targets(), ["maker"]);
    }

    #[test]
    fn several_account_attributes_on_one_field_accumulate() {
        let parsed = constraints("#[account(mut)] #[account(has_one = authority)]");
        assert_eq!(parsed.len(), 2);
        assert!(parsed.is_mut());
        assert_eq!(parsed.has_one_targets(), ["authority"]);
    }

    #[test]
    fn unknown_constraints_are_retained_rather_than_dropped() {
        assert_eq!(
            kinds("#[account(some_future_thing = 3)]"),
            [ConstraintKind::Other {
                key: "some_future_thing".into(),
                value: Some("3".into())
            }]
        );
    }

    #[test]
    fn assertion_queries_read_custom_constraints() {
        assert!(constraints("#[account(constraint = authority.is_signer)]").asserts_signer());
        assert!(constraints("#[account(signer)]").asserts_signer());
        assert!(!constraints("#[account(mut)]").asserts_signer());

        assert!(constraints("#[account(owner = token_program.key())]").asserts_owner());
        assert!(constraints("#[account(constraint = v.owner == id())]").asserts_owner());

        assert!(constraints("#[account(address = sysvar::rent::ID)]").asserts_address());
        assert!(constraints("#[account(constraint = a.key() == b)]").asserts_address());
    }

    #[test]
    fn non_account_attributes_are_ignored() {
        let field = field_with("#[doc = \"hello\"] #[serde(skip)]");
        assert!(parse(&field.attrs, FileId(0)).is_empty());
    }

    #[test]
    fn constraints_record_where_they_were_written() {
        let parsed = constraints("#[account(mut)]");
        let at = parsed.items[0].location;
        assert_eq!(at.start.line, 1);
        assert!(at.start.column > 1);
    }
}
