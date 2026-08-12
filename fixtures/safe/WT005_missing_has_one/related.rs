//! WT005 safe — the three ways a stored relationship is legitimately enforced.
//!
//! Only one of them is `has_one`. A rule that recognises no other spelling
//! reports two-thirds of correct code as a High-severity finding.

use anchor_lang::prelude::*;

declare_id!("Rel111111111111111111111111111111111111111");

#[program]
pub mod safe_treasury {
    use super::*;

    pub fn withdraw_has_one(ctx: Context<WithdrawHasOne>, amount: u64) -> Result<()> {
        ctx.accounts.treasury.balance = ctx.accounts.treasury.balance.saturating_sub(amount);
        Ok(())
    }

    pub fn withdraw_constraint(ctx: Context<WithdrawConstraint>, amount: u64) -> Result<()> {
        ctx.accounts.treasury.balance = ctx.accounts.treasury.balance.saturating_sub(amount);
        Ok(())
    }

    pub fn withdraw_pda(ctx: Context<WithdrawPda>, amount: u64) -> Result<()> {
        ctx.accounts.treasury.balance = ctx.accounts.treasury.balance.saturating_sub(amount);
        Ok(())
    }
}

/// The idiomatic spelling.
#[derive(Accounts)]
pub struct WithdrawHasOne<'info> {
    #[account(mut, has_one = authority)]
    pub treasury: Account<'info, Treasury>,
    pub authority: Signer<'info>,
}

/// The same assertion written by hand, which programs do when the error needs
/// to be domain-specific.
#[derive(Accounts)]
pub struct WithdrawConstraint<'info> {
    #[account(
        mut,
        constraint = treasury.authority == authority.key() @ TreasuryError::WrongAuthority,
    )]
    pub treasury: Account<'info, Treasury>,
    pub authority: Signer<'info>,
}

/// The relationship enforced by derivation rather than by comparison. The
/// treasury's address *is* a function of the authority, so an authority that
/// did not derive this address cannot produce it. This is stronger than
/// `has_one`, and a naive rule flags it because the word `has_one` is absent.
#[derive(Accounts)]
pub struct WithdrawPda<'info> {
    #[account(
        mut,
        seeds = [b"treasury", authority.key().as_ref()],
        bump = treasury.bump,
    )]
    pub treasury: Account<'info, Treasury>,
    pub authority: Signer<'info>,
}

#[account]
pub struct Treasury {
    pub authority: Pubkey,
    pub balance: u64,
    pub bump: u8,
}

#[error_code]
pub enum TreasuryError {
    #[msg("this treasury belongs to another authority")]
    WrongAuthority,
}
