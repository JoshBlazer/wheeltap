//! WT005 — a relationship the account records but the program never checks.
//!
//! `Treasury` stores an `authority: Pubkey`. `Withdraw` takes both a treasury
//! and an `authority` that signs. The signature is real — but nothing ties the
//! signer to *this* treasury.
//!
//! So an attacker signs with their own key, passes someone else's treasury, and
//! the constraint that would have stopped them (`has_one = authority`) is
//! simply absent. The field's existence documents an intended relationship that
//! the account list never enforces.

use anchor_lang::prelude::*;

declare_id!("Trea111111111111111111111111111111111111111");

#[program]
pub mod treasury {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let treasury = &mut ctx.accounts.treasury;
        treasury.balance = treasury
            .balance
            .checked_sub(amount)
            .ok_or(TreasuryError::Insufficient)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut)]
    pub treasury: Account<'info, Treasury>,

    /// Signs, but is never checked against `treasury.authority`.
    pub authority: Signer<'info>,
}

#[account]
pub struct Treasury {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum TreasuryError {
    #[msg("not enough in the treasury")]
    Insufficient,
}
