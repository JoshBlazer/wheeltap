//! WT003 — unchecked arithmetic on balances.
//!
//! Solana programs ship as release builds, and release builds wrap on overflow
//! unless `overflow-checks` is turned on explicitly. There is no Cargo.toml
//! here enabling it, so every one of these operations wraps silently.
//!
//! `stake.amount + amount` wrapping to a small number turns a large deposit
//! into a small balance. `rewards * multiplier` wrapping turns a modest stake
//! into an enormous payout. Neither errors; both just produce the wrong number
//! and carry on.

use anchor_lang::prelude::*;

declare_id!("Stake11111111111111111111111111111111111111");

#[program]
pub mod staking {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, amount: u64) -> Result<()> {
        let stake = &mut ctx.accounts.stake;

        stake.amount = stake.amount + amount;
        stake.total_deposited += amount;

        let pool = &mut ctx.accounts.pool;
        pool.total_staked = pool.total_staked + amount;

        Ok(())
    }

    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let stake = &mut ctx.accounts.stake;
        let elapsed = Clock::get()?.unix_timestamp - stake.last_claim;

        let rewards = stake.amount * ctx.accounts.pool.reward_rate * elapsed as u64;

        stake.pending_rewards += rewards;
        stake.last_claim = Clock::get()?.unix_timestamp;

        ctx.accounts.pool.remaining_rewards -= rewards;
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

#[derive(Accounts)]
pub struct Claim<'info> {
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
    pub total_deposited: u64,
    pub pending_rewards: u64,
    pub last_claim: i64,
}

#[account]
pub struct Pool {
    pub total_staked: u64,
    pub reward_rate: u64,
    pub remaining_rewards: u64,
}
