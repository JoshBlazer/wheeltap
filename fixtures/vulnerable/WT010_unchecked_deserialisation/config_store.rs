//! WT010 — deserialising without the discriminator check.
//!
//! Anchor writes an eight-byte discriminator at the front of every account it
//! owns, derived from the account's type name. `try_deserialize` checks it;
//! `try_deserialize_unchecked` does not.
//!
//! Skipping it means any account owned by this program can be read as any type.
//! An attacker passes a `UserProfile` where a `Config` is expected, the bytes
//! line up differently, and the program acts on whatever the reinterpretation
//! produces — typically with the attacker's key sitting where the admin key
//! should be.

use anchor_lang::prelude::*;

declare_id!("Desr111111111111111111111111111111111111111");

#[program]
pub mod config_store {
    use super::*;

    pub fn read_config(ctx: Context<ReadConfig>) -> Result<()> {
        let mut data: &[u8] = &ctx.accounts.config.try_borrow_data()?;
        let config = Config::try_deserialize_unchecked(&mut data)?;

        require_keys_eq!(
            config.admin,
            ctx.accounts.caller.key(),
            StoreError::NotAdmin
        );

        msg!("fee is {}", config.fee_bps);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ReadConfig<'info> {
    pub caller: Signer<'info>,

    /// CHECK: owner checked below
    #[account(owner = crate::ID)]
    pub config: AccountInfo<'info>,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub fee_bps: u16,
}

#[error_code]
pub enum StoreError {
    #[msg("caller is not the admin")]
    NotAdmin,
}
