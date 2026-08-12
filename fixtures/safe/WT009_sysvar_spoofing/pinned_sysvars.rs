//! WT009 safe — sysvars whose address is established, and ordinary accounts
//! that merely have sysvar-ish names.

use anchor_lang::prelude::*;
use anchor_lang::solana_program::sysvar;

declare_id!("Sys111111111111111111111111111111111111111");

#[program]
pub mod safe_vesting {
    use super::*;

    /// The typed form: `Sysvar<'info, T>` asserts the address.
    pub fn claim_typed(ctx: Context<ClaimTyped>) -> Result<()> {
        require!(
            ctx.accounts.clock.unix_timestamp >= ctx.accounts.grant.unlocks_at,
            VestingError::StillLocked
        );
        Ok(())
    }

    /// The address pinned by constraint, which programs use for the sysvars
    /// Anchor has no type for — the instructions sysvar, most often.
    pub fn claim_pinned(ctx: Context<ClaimPinned>) -> Result<()> {
        msg!("instructions sysvar: {}", ctx.accounts.instructions.key());
        Ok(())
    }

    /// Nothing to do with sysvars. `clock_authority` is a plain account that
    /// happens to contain the word, and `rent_collector` is a destination for
    /// rent, not the rent sysvar. A name-matching rule flags both.
    pub fn administer(ctx: Context<Administer>) -> Result<()> {
        msg!("collector: {}", ctx.accounts.rent_collector.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ClaimTyped<'info> {
    #[account(mut, has_one = beneficiary)]
    pub grant: Account<'info, Grant>,
    pub beneficiary: Signer<'info>,
    pub clock: Sysvar<'info, Clock>,
}

#[derive(Accounts)]
pub struct ClaimPinned<'info> {
    pub beneficiary: Signer<'info>,

    /// CHECK: address pinned to the instructions sysvar
    #[account(address = sysvar::instructions::ID)]
    pub instructions: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct Administer<'info> {
    #[account(mut, has_one = clock_authority)]
    pub grant: Account<'info, Grant>,

    pub clock_authority: Signer<'info>,

    #[account(mut)]
    pub rent_collector: SystemAccount<'info>,
}

#[account]
pub struct Grant {
    pub beneficiary: Pubkey,
    pub clock_authority: Pubkey,
    pub unlocks_at: i64,
}

#[error_code]
pub enum VestingError {
    #[msg("this grant has not vested yet")]
    StillLocked,
}
