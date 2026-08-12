//! WT008 — a manual close that leaves the account revivable.
//!
//! Draining the lamports is not closing the account. The runtime only reclaims
//! an account at the *end* of a transaction, and only if its balance is zero.
//! Until then the data is untouched, and anyone can top the balance back up
//! within the same transaction.
//!
//! So the attacker calls `close_position`, then in the same transaction sends
//! a few lamports back. The account survives with all its data intact — a
//! position that has already been paid out and now looks unpaid.
//!
//! Anchor's `close = destination` constraint drains, zeroes, and assigns the
//! account to the system program. Doing it by hand means doing all three.

use anchor_lang::prelude::*;

declare_id!("Clos111111111111111111111111111111111111111");

#[program]
pub mod closer {
    use super::*;

    pub fn close_position(ctx: Context<ClosePosition>) -> Result<()> {
        let position = ctx.accounts.position.to_account_info();
        let destination = ctx.accounts.owner.to_account_info();

        let balance = position.lamports();
        **position.try_borrow_mut_lamports()? = 0;
        **destination.try_borrow_mut_lamports()? += balance;

        Ok(())
    }
}

#[derive(Accounts)]
pub struct ClosePosition<'info> {
    #[account(mut, has_one = owner)]
    pub position: Account<'info, Position>,

    #[account(mut)]
    pub owner: Signer<'info>,
}

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub size: u64,
    pub settled: bool,
}
