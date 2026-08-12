//! Arithmetic identical to the WT003 vulnerable fixture, in a project whose
//! `Cargo.toml` sets `overflow-checks = true`. It panics rather than wraps, so
//! it must not be reported.

use anchor_lang::prelude::*;

declare_id!("Ovf111111111111111111111111111111111111111");

#[program]
pub mod overflow_checked_program {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let stake = &mut ctx.accounts.stake;
        stake.amount = stake.amount + amount;
        stake.total_deposited += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, has_one = owner)]
    pub stake: Account<'info, Stake>,
    pub owner: Signer<'info>,
}

#[account]
pub struct Stake {
    pub owner: Pubkey,
    pub amount: u64,
    pub total_deposited: u64,
}
