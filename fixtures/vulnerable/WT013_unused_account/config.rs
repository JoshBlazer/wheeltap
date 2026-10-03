//! WT013 — an admin account that nothing uses.
//!
//! `admin` is declared, carries a `CHECK` comment claiming a validation, and is
//! then never read: not by the handler, not by any constraint. Anyone can call
//! `set_fee_bps`. The comment is not a check; it is a note.
//!
//! This was a documented known gap for WT001, which cannot flag it without
//! matching on names (`fixtures/known_gaps/README.md` says why that was
//! rejected). WT013 catches it from a different direction: whatever `admin`
//! was meant to prove, nothing ever asks it to prove anything.

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
