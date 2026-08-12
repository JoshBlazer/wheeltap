//! WT002 safe — the owner asserted in the handler body rather than by
//! constraint.
//!
//! Anchor constraints are the idiomatic place for this, but plenty of real code
//! asserts in the function instead, especially where the expected owner depends
//! on state that constraints cannot reach. A rule that only recognises
//! `#[account(owner = ...)]` calls this a critical vulnerability, and it is not
//! one.
//!
//! This is the case that forces the detector to look inside the handler, and
//! the reason its findings are `confidence: medium` — the check is found by
//! reading one function, so a check made in a *called* function is still
//! missed. That limit is documented rather than hidden.

use anchor_lang::prelude::*;

declare_id!("Body11111111111111111111111111111111111111");

#[program]
pub mod safe_registry {
    use super::*;

    pub fn read_entry(ctx: Context<ReadEntry>) -> Result<()> {
        // The owning program is asserted here, before the bytes are trusted.
        require_keys_eq!(
            *ctx.accounts.entry.owner,
            ctx.accounts.registry.authority_program,
            RegistryError::WrongOwner
        );

        let data = ctx.accounts.entry.try_borrow_data()?;
        let parsed = Entry::try_from_slice(&data)?;
        msg!("entry version {}", parsed.version);

        Ok(())
    }

    pub fn read_entry_with_early_return(ctx: Context<ReadEntry>) -> Result<()> {
        if ctx.accounts.entry.owner != &ctx.accounts.registry.authority_program {
            return err!(RegistryError::WrongOwner);
        }

        let data = ctx.accounts.entry.try_borrow_data()?;
        let parsed = Entry::try_from_slice(&data)?;
        msg!("entry version {}", parsed.version);

        Ok(())
    }
}

#[derive(Accounts)]
pub struct ReadEntry<'info> {
    pub registry: Account<'info, Registry>,

    /// CHECK: owner asserted against the registry in the handler
    pub entry: AccountInfo<'info>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct Entry {
    pub version: u8,
}

#[account]
pub struct Registry {
    pub authority_program: Pubkey,
}

#[error_code]
pub enum RegistryError {
    #[msg("entry is not owned by the expected program")]
    WrongOwner,
}
