//! Integration tests against the vendored real-program corpus.
//!
//! These do not test detector correctness — that is what `fixtures/vulnerable`
//! and `fixtures/safe` are for. They test that the analyser survives real code
//! and models it accurately, which is the Phase 1 exit criterion.
//!
//! Expected counts are asserted exactly rather than as lower bounds. A count
//! that drifts is either a modelling improvement worth recording or a
//! regression worth catching, and "at least N" hides both.

use std::path::{Path, PathBuf};

use wheeltap_core::ProgramContext;

fn corpus(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("fixtures/corpus")
        .join(name)
}

fn scan(name: &str) -> ProgramContext {
    ProgramContext::scan(&corpus(name))
}

#[test]
fn escrow_is_modelled_accurately() {
    let ctx = scan("escrow");

    assert_eq!(ctx.programs.len(), 1);
    assert_eq!(ctx.programs[0].name, "escrow");

    // Two instructions, each delegating to helpers that also take a Context.
    let entrypoints: Vec<_> = ctx.entrypoints().map(|h| h.name.as_str()).collect();
    assert_eq!(entrypoints, ["make_offer", "take_offer"]);
    assert_eq!(ctx.handlers.len(), 6, "two entrypoints and four delegated");

    assert_eq!(ctx.accounts.len(), 2);
    assert_eq!(ctx.states.len(), 1);
    assert!(ctx.looks_like_anchor());
    assert!(ctx.diagnostics.is_empty(), "{:?}", ctx.diagnostics);
}

/// The specific modelling facts a detector will rely on, on real code.
#[test]
fn escrow_field_types_and_constraints_are_read_correctly() {
    let ctx = scan("escrow");
    let take = ctx
        .accounts_struct("TakeOffer")
        .expect("TakeOffer modelled");

    let taker = take.field("taker").expect("taker field");
    assert!(taker.ty.is_signer_checked());
    assert!(taker.constraints.is_mut());

    let offer = take.field("offer").expect("offer field");
    assert!(offer.ty.is_owner_checked(), "Account<T> is owner-checked");
    assert_eq!(
        offer.constraints.has_one_targets(),
        ["maker", "token_mint_a", "token_mint_b"]
    );
    assert!(offer.constraints.is_pda());
    assert_eq!(
        offer.constraints.bump_is_canonical(),
        Some(false),
        "TakeOffer re-derives the stored bump: `bump = offer.bump`"
    );

    // Box<InterfaceAccount<..>> must read exactly as the unboxed form.
    let account = take
        .field("taker_token_account_a")
        .expect("taker_token_account_a field");
    assert!(account.ty.boxed);
    assert!(account.ty.is_owner_checked());
    assert!(!account.ty.is_unchecked());
}

#[test]
fn every_handler_resolves_to_an_accounts_struct_it_can_see() {
    for name in ["escrow", "anchor-misc", "drift"] {
        let ctx = scan(name);
        let unresolved: Vec<_> = ctx
            .handlers
            .iter()
            .filter(|h| ctx.handler_accounts(h).is_none())
            .map(|h| {
                format!(
                    "{}::{}",
                    h.item_path,
                    h.accounts_struct.as_deref().unwrap_or("-")
                )
            })
            .collect();
        assert!(
            unresolved.is_empty(),
            "{name}: handlers pointing at Accounts structs the scan never saw: {unresolved:?}"
        );
    }
}

/// Anchor's own test programs exercise nearly every constraint form the
/// framework supports, including the awkward ones.
#[test]
fn anchor_misc_constraint_coverage_is_modelled() {
    let ctx = scan("anchor-misc");

    assert_eq!(ctx.programs.len(), 6);
    assert_eq!(ctx.accounts.len(), 145);
    assert_eq!(ctx.handlers.len(), 141);
    assert!(ctx.diagnostics.is_empty(), "{:?}", ctx.diagnostics);

    assert_eq!(constraint_kinds(&ctx).len(), 527);
}

/// The constraint forms Wheeltap models are exercised across the corpus. No
/// single program uses all of them — `anchor-misc` has no `has_one` at all,
/// and drift is where the assertion-style constraints live — so coverage is
/// asserted where each form actually occurs.
#[test]
fn every_modelled_constraint_form_appears_somewhere_in_the_corpus() {
    let init_and_pda = constraint_kinds(&scan("anchor-misc"));
    for form in [
        "mut",
        "init",
        "init_if_needed",
        "zero",
        "seeds",
        "bump",
        "payer",
        "space",
        "token::mint",
        "associated_token::authority",
    ] {
        assert!(
            init_and_pda.iter().any(|c| c.starts_with(form)),
            "anchor-misc should exercise `{form}`"
        );
    }

    let assertions = constraint_kinds(&scan("drift"));
    for form in ["has_one", "constraint", "address", "close", "realloc"] {
        assert!(
            assertions.iter().any(|c| c.starts_with(form)),
            "drift should exercise `{form}`"
        );
    }
}

/// Every constraint in a context, as written.
fn constraint_kinds(ctx: &ProgramContext) -> Vec<String> {
    ctx.accounts
        .iter()
        .flat_map(|a| a.fields.iter())
        .flat_map(|f| f.constraints.iter())
        .map(|c| c.raw.clone())
        .collect()
}

/// The production-scale target. This is the test that would catch a
/// pathological slowdown or a panic on real code.
#[test]
fn drift_scans_without_panicking() {
    let ctx = scan("drift");

    assert_eq!(ctx.sources.len(), 116);
    assert!(ctx.sources.iter().map(|f| f.line_count()).sum::<usize>() > 70_000);
    assert_eq!(ctx.accounts.len(), 155);
    assert_eq!(ctx.states.len(), 27);
    assert!(ctx.diagnostics.is_empty(), "{:?}", ctx.diagnostics);

    // All 262 handlers are delegated: this vendored commit has the entire
    // `#[program]` dispatch module commented out. Modelling only entrypoints
    // would therefore see nothing at all here, which is why handlers are
    // recognised wherever they are declared.
    assert_eq!(ctx.handlers.len(), 262);
    assert_eq!(ctx.entrypoints().count(), 0);
}

/// Build spec invariant 4: two runs over identical input must agree exactly.
#[test]
fn scanning_is_deterministic() {
    for name in ["escrow", "anchor-misc"] {
        let first = serde_json::to_string(&scan(name).summary()).expect("serialise");
        let second = serde_json::to_string(&scan(name).summary()).expect("serialise");
        assert_eq!(first, second, "{name}: two scans disagreed");
    }
}
