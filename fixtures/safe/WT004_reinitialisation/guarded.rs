//! WT004 safe — the two legitimate uses of `init_if_needed`.
//!
//! This constraint is not a bug in itself; it exists because two real patterns
//! need it. A rule that flags every occurrence is flagging a language feature.

use anchor_lang::prelude::*;
use anchor_spl::associated_token::AssociatedToken;
use anchor_spl::token_interface::{Mint, TokenAccount, TokenInterface};

declare_id!("Grd111111111111111111111111111111111111111");

#[program]
pub mod safe_registry {
    use super::*;

    /// Creating an associated token account if the user does not have one yet.
    /// This is *the* idiomatic use of `init_if_needed`, it appears in almost
    /// every program that moves tokens, and it is not a reinitialisation
    /// hazard: a token account's state is owned by the token program, not by us,
    /// and nothing here overwrites it.
    pub fn ensure_token_account(ctx: Context<EnsureTokenAccount>) -> Result<()> {
        msg!("token account ready: {}", ctx.accounts.recipient_ata.key());
        Ok(())
    }

    /// Program state, but guarded: the handler asks whether the account is
    /// already live before touching the fields that establish ownership.
    pub fn create_or_update_profile(ctx: Context<CreateOrUpdate>, handle: String) -> Result<()> {
        let profile = &mut ctx.accounts.profile;

        if profile.authority == Pubkey::default() {
            // Fresh account: claim it.
            profile.authority = ctx.accounts.payer.key();
        } else {
            // Existing account: only its owner may change it.
            require_keys_eq!(
                profile.authority,
                ctx.accounts.payer.key(),
                RegistryError::NotTheOwner
            );
        }

        profile.handle = handle;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct EnsureTokenAccount<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub mint: InterfaceAccount<'info, Mint>,

    #[account(
        init_if_needed,
        payer = payer,
        associated_token::mint = mint,
        associated_token::authority = payer,
        associated_token::token_program = token_program,
    )]
    pub recipient_ata: InterfaceAccount<'info, TokenAccount>,

    pub token_program: Interface<'info, TokenInterface>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct CreateOrUpdate<'info> {
    #[account(
        init_if_needed,
        payer = payer,
        space = 8 + Profile::INIT_SPACE,
        seeds = [b"profile", payer.key().as_ref()],
        bump,
    )]
    pub profile: Account<'info, Profile>,

    #[account(mut)]
    pub payer: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct Profile {
    pub authority: Pubkey,
    pub handle: String,
}

#[error_code]
pub enum RegistryError {
    #[msg("this profile belongs to someone else")]
    NotTheOwner,
}
