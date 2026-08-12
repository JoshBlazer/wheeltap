//! WT001 safe — `has_one` targets that are not authorities.
//!
//! A rule keyed on "is the target of a `has_one`" would flag every one of
//! these. `has_one` expresses *any* recorded relationship between accounts, and
//! most of those relationships have nothing to do with authorisation: a pool
//! records its mint, an offer records the token it wants, a position records
//! its market. None of them signs anything, and none of them should.
//!
//! The account that must sign is the one already typed `Signer`.

use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, TokenAccount};

declare_id!("HasOne11111111111111111111111111111111111");

#[program]
pub mod pool {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        ctx.accounts.pool.total_deposited = ctx
            .accounts
            .pool
            .total_deposited
            .checked_add(amount)
            .ok_or(PoolError::Overflow)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    /// The only account that needs to sign, and it does.
    #[account(mut)]
    pub depositor: Signer<'info>,

    #[account(
        mut,
        has_one = mint,
        has_one = treasury,
        has_one = depositor,
    )]
    pub pool: Account<'info, Pool>,

    /// Recorded on the pool, but a mint does not sign.
    pub mint: Account<'info, Mint>,

    /// Nor does a treasury token account.
    #[account(mut)]
    pub treasury: Account<'info, TokenAccount>,
}

#[account]
pub struct Pool {
    pub mint: Pubkey,
    pub treasury: Pubkey,
    pub depositor: Pubkey,
    pub total_deposited: u64,
}

#[error_code]
pub enum PoolError {
    #[msg("deposit would overflow the pool total")]
    Overflow,
}
