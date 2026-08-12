//! WT003 safe — arithmetic that is either checked, or cannot overflow.
//!
//! The naive rule is "flag `+`, `-`, `*`", and it drowns the user. Most
//! arithmetic in a program is not on balances at all: loop counters, slice
//! lengths, offsets into a buffer, sizes computed from constants. Flagging
//! those trains people to ignore the rule, and then they ignore the one that
//! mattered.

use anchor_lang::prelude::*;

declare_id!("Chkd111111111111111111111111111111111111111");

pub const ANCHOR_DISCRIMINATOR: usize = 8;
pub const MAX_ENTRIES: usize = 32;

#[program]
pub mod safe_staking {
    use super::*;

    /// Every balance operation is checked and returns an error on overflow.
    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let stake = &mut ctx.accounts.stake;

        stake.amount = stake
            .amount
            .checked_add(amount)
            .ok_or(StakeError::Overflow)?;

        ctx.accounts.pool.total_staked = ctx
            .accounts
            .pool
            .total_staked
            .checked_add(amount)
            .ok_or(StakeError::Overflow)?;

        Ok(())
    }

    /// Saturating arithmetic is a deliberate, documented choice: a balance that
    /// clamps at zero rather than wrapping to `u64::MAX`.
    pub fn slash(ctx: Context<Deposit>, penalty: u64) -> Result<()> {
        let stake = &mut ctx.accounts.stake;
        stake.amount = stake.amount.saturating_sub(penalty);
        Ok(())
    }

    /// None of this is a balance. Indices, lengths, and sizes derived from
    /// constants cannot overflow a `u64` in any reachable state.
    pub fn compact(ctx: Context<Deposit>) -> Result<()> {
        let entries = &mut ctx.accounts.pool.entries;

        let mut i = 0;
        while i + 1 < entries.len() {
            if entries[i] == 0 {
                entries.remove(i);
            } else {
                i += 1;
            }
        }

        let space = ANCHOR_DISCRIMINATOR + 8 * MAX_ENTRIES;
        msg!("compacted to {} entries, {} bytes", entries.len() - 1, space);

        Ok(())
    }
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    #[account(mut, has_one = owner)]
    pub stake: Account<'info, Stake>,
    #[account(mut)]
    pub pool: Account<'info, Pool>,
    pub owner: Signer<'info>,
}

#[account]
pub struct Stake {
    pub owner: Pubkey,
    pub amount: u64,
}

#[account]
pub struct Pool {
    pub total_staked: u64,
    pub entries: Vec<u64>,
}

#[error_code]
pub enum StakeError {
    #[msg("arithmetic overflow")]
    Overflow,
}
