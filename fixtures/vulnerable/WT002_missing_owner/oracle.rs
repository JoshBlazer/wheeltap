//! WT002 — deserialising an account without checking who owns it.
//!
//! `oracle` is an `AccountInfo`, so Anchor validates nothing about it. The
//! handler reads its bytes and trusts them as a price.
//!
//! An attacker creates an account owned by *their* program, writes whatever
//! price suits them, and passes it here. Nothing in this program can tell the
//! difference: account data is just bytes, and the only thing distinguishing a
//! real price feed from a forged one is the program that owns it.
//!
//! This is how oracle-manipulation exploits usually start.

use anchor_lang::prelude::*;

declare_id!("Orac1e11111111111111111111111111111111111");

#[program]
pub mod lending {
    use super::*;

    pub fn borrow(ctx: Context<Borrow>, amount: u64) -> Result<()> {
        let data = ctx.accounts.oracle.try_borrow_data()?;
        let feed = PriceFeed::try_from_slice(&data)?;

        let collateral_value = ctx.accounts.position.collateral * feed.price;
        require!(
            collateral_value >= amount * 2,
            LendingError::Undercollateralised
        );

        ctx.accounts.position.borrowed += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Borrow<'info> {
    #[account(mut, has_one = owner)]
    pub position: Account<'info, Position>,

    pub owner: Signer<'info>,

    /// CHECK: the price feed for this market
    pub oracle: AccountInfo<'info>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct PriceFeed {
    pub price: u64,
    pub published_at: i64,
}

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub collateral: u64,
    pub borrowed: u64,
}

#[error_code]
pub enum LendingError {
    #[msg("position is undercollateralised")]
    Undercollateralised,
}
