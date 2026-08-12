//! WT009 — a sysvar the caller can substitute.
//!
//! `clock` is an `AccountInfo` with no address constraint, and the handler
//! deserialises it as the real clock. Sysvar accounts are ordinary accounts at
//! fixed, well-known addresses; nothing stops a caller passing a different
//! account entirely.
//!
//! Here that means passing a "clock" whose timestamp is far in the future, and
//! unlocking a vesting schedule that has not vested.
//!
//! `Sysvar<'info, Clock>` asserts the address. So does
//! `#[account(address = sysvar::clock::ID)]`. Both are one line.

use anchor_lang::prelude::*;

declare_id!("Clk111111111111111111111111111111111111111");

#[program]
pub mod vesting {
    use super::*;

    pub fn claim(ctx: Context<Claim>) -> Result<()> {
        let clock = Clock::from_account_info(&ctx.accounts.clock)?;

        require!(
            clock.unix_timestamp >= ctx.accounts.grant.unlocks_at,
            VestingError::StillLocked
        );

        ctx.accounts.grant.claimed = true;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Claim<'info> {
    #[account(mut, has_one = beneficiary)]
    pub grant: Account<'info, Grant>,

    pub beneficiary: Signer<'info>,

    /// CHECK: the clock sysvar
    pub clock: AccountInfo<'info>,
}

#[account]
pub struct Grant {
    pub beneficiary: Pubkey,
    pub unlocks_at: i64,
    pub claimed: bool,
}

#[error_code]
pub enum VestingError {
    #[msg("this grant has not vested yet")]
    StillLocked,
}
