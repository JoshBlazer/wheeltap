//! WT011 — two mutable accounts that can be the same account.
//!
//! Nothing stops a caller passing the same address for `from` and `to`. Anchor
//! deserialises it twice, into two independent in-memory copies. The handler
//! debits one copy and credits the other, and whichever is written back last
//! wins.
//!
//! Here that means calling `transfer` on yourself, twice, and ending up with
//! the credit but not the debit: `from.balance - amount` is discarded when the
//! `to` copy is serialised over it. Free money, in a loop.

use anchor_lang::prelude::*;

declare_id!("Dup111111111111111111111111111111111111111");

#[program]
pub mod ledger {
    use super::*;

    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        let from = &mut ctx.accounts.from;
        from.balance = from.balance.checked_sub(amount).ok_or(LedgerError::Short)?;

        let to = &mut ctx.accounts.to;
        to.balance = to.balance.checked_add(amount).ok_or(LedgerError::Short)?;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut, has_one = owner)]
    pub from: Account<'info, Balance>,

    #[account(mut)]
    pub to: Account<'info, Balance>,

    pub owner: Signer<'info>,
}

#[account]
pub struct Balance {
    pub owner: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum LedgerError {
    #[msg("balance too low")]
    Short,
}
