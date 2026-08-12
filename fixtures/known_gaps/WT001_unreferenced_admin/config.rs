//! WT001 — an admin account that is never required to sign.
//!
//! The second common shape: an authority-by-name account left as
//! `UncheckedAccount` with a `CHECK` comment asserting a validation that does
//! not exist anywhere. The comment is not a check; it is a note.

use anchor_lang::prelude::*;

declare_id!("Cfg111111111111111111111111111111111111111");

#[program]
pub mod config {
    use super::*;

    pub fn set_fee_bps(ctx: Context<SetFee>, fee_bps: u16) -> Result<()> {
        require!(fee_bps <= 10_000, ConfigError::FeeTooHigh);
        ctx.accounts.config.fee_bps = fee_bps;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct SetFee<'info> {
    #[account(mut, seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    /// CHECK: only the protocol admin can call this
    pub admin: UncheckedAccount<'info>,
}

#[account]
pub struct Config {
    pub fee_bps: u16,
    pub bump: u8,
}

#[error_code]
pub enum ConfigError {
    #[msg("fee may not exceed 100%")]
    FeeTooHigh,
}
