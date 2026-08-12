//! WT001 — the canonical missing-signer bug.
//!
//! `has_one = authority` proves the account passed as `authority` is the key
//! the vault recorded. It proves nothing about whether that key *signed*. Any
//! transaction can pass the real authority's public key, because public keys
//! are public — so anyone can drain this vault.
//!
//! Fixing it is one word: `Signer<'info>`.

use anchor_lang::prelude::*;

declare_id!("Vau1t1111111111111111111111111111111111111");

#[program]
pub mod vault {
    use super::*;

    pub fn withdraw(ctx: Context<Withdraw>, amount: u64) -> Result<()> {
        let vault = &mut ctx.accounts.vault;
        vault.balance = vault
            .balance
            .checked_sub(amount)
            .ok_or(VaultError::InsufficientFunds)?;

        **vault.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.destination.try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Withdraw<'info> {
    #[account(mut, has_one = authority)]
    pub vault: Account<'info, Vault>,

    /// CHECK: the vault records this key, so it must be the right authority
    pub authority: AccountInfo<'info>,

    #[account(mut)]
    pub destination: SystemAccount<'info>,
}

#[account]
pub struct Vault {
    pub authority: Pubkey,
    pub balance: u64,
}

#[error_code]
pub enum VaultError {
    #[msg("not enough funds in the vault")]
    InsufficientFunds,
}
