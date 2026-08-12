//! WT001 safe — the three ways a signature is legitimately required.
//!
//! All three of these are correct code. A detector that flags any of them is
//! telling a developer to "fix" something that is already right, which is how
//! a security tool gets switched off.

use anchor_lang::prelude::*;

declare_id!("Safe11111111111111111111111111111111111111");

#[program]
pub mod safe_vault {
    use super::*;

    pub fn withdraw_typed(ctx: Context<WithdrawTyped>, amount: u64) -> Result<()> {
        ctx.accounts.vault.balance = ctx.accounts.vault.balance.saturating_sub(amount);
        Ok(())
    }

    pub fn withdraw_constrained(ctx: Context<WithdrawConstrained>, amount: u64) -> Result<()> {
        ctx.accounts.vault.balance = ctx.accounts.vault.balance.saturating_sub(amount);
        Ok(())
    }

    pub fn withdraw_asserted(ctx: Context<WithdrawAsserted>, amount: u64) -> Result<()> {
        ctx.accounts.vault.balance = ctx.accounts.vault.balance.saturating_sub(amount);
        Ok(())
    }
}

/// The idiomatic fix: the type carries the requirement.
#[derive(Accounts)]
pub struct WithdrawTyped<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,
    pub authority: Signer<'info>,
}

/// Older code requires the signature by constraint instead. Still correct.
#[derive(Accounts)]
pub struct WithdrawConstrained<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    /// CHECK: the `signer` constraint enforces the signature
    #[account(signer)]
    pub authority: AccountInfo<'info>,
}

/// And some assert it explicitly, with a domain error.
#[derive(Accounts)]
pub struct WithdrawAsserted<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    /// CHECK: asserted below
    #[account(constraint = authority.is_signer @ VaultError::AuthorityMustSign)]
    pub authority: AccountInfo<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("the authority must sign")]
    AuthorityMustSign,
}
