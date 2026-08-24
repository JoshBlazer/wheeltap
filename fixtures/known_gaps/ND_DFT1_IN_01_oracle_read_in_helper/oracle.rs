//! Known gap — an unchecked account whose data is read inside a helper.
//!
//! This is ND-DFT1-IN-01, "Admin Can Pass Invalid Oracle Accounts", reduced to
//! its shape. The `oracle` is an `AccountInfo` with no owner constraint and a
//! `/// CHECK:` comment promising validation that does not happen. Its price is
//! read and written into the market.
//!
//! Wheeltap reports nothing, and this was verified against the real thing:
//! scanning drift's `admin.rs` at `ac4bfd00e92105adba9809bcf1dfc50b3eb278ae` —
//! the revision Neodyme cite, before the fix — also yields zero findings.
//!
//! **Why it is missed.** WT002 fires when an unvalidated account's data is
//! deserialised *in the handler*. Here the read is `get_price(&oracle)`, one
//! call away, so the handler body contains no deserialisation for the rule to
//! see. This is the intraprocedural boundary from ADR-001, and it cuts both
//! ways: the same limit that stops WT002 reporting drift's zero-copy loaders as
//! critical also stops it reporting this.
//!
//! **What catching it would need.** A call graph, or at minimum a summary of
//! which functions dereference an `AccountInfo`'s data, propagated to callers.
//! That is the first genuinely interprocedural analysis the tool would have,
//! and it is the natural next step rather than a tweak.
//!
//! The `/// CHECK:` comment is worth noting on its own. Anchor requires one on
//! every `AccountInfo`, so its presence proves only that the compiler insisted.
//! Here it names a validation the code does not perform.

use anchor_lang::prelude::*;

declare_id!("Orc111111111111111111111111111111111111111");

#[program]
pub mod oracle_gap {
    use super::*;

    pub fn initialize_market(ctx: Context<InitializeMarket>) -> Result<()> {
        // The read happens in `get_price`, so nothing in this body looks like
        // a deserialisation of an unvalidated account.
        let price = get_price(&ctx.accounts.oracle)?;

        let market = &mut ctx.accounts.market;
        market.oracle = ctx.accounts.oracle.key();
        market.last_price = price;
        Ok(())
    }
}

/// Reads the account's data with no check on who owns it. An attacker-supplied
/// account of the right length is read as a price feed.
fn get_price(oracle: &AccountInfo) -> Result<u64> {
    let data = oracle.try_borrow_data()?;
    Ok(u64::from_le_bytes(
        data[0..8].try_into().map_err(|_| ErrorCode::BadOracle)?,
    ))
}

#[derive(Accounts)]
pub struct InitializeMarket<'info> {
    #[account(mut, has_one = admin)]
    pub market: Account<'info, Market>,

    /// CHECK: checked in `initialize_market`
    pub oracle: AccountInfo<'info>,

    pub admin: Signer<'info>,
}

#[account]
pub struct Market {
    pub admin: Pubkey,
    pub oracle: Pubkey,
    pub last_price: u64,
}

#[error_code]
pub enum ErrorCode {
    #[msg("oracle account could not be read")]
    BadOracle,
}
