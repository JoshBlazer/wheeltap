//! WT004 — `init_if_needed` on program state, with no guard.
//!
//! `init_if_needed` runs the handler on both a freshly created account and one
//! that already exists and holds state. The handler below cannot tell which,
//! and writes `authority` unconditionally.
//!
//! So the second call takes the account over. An attacker passes someone else's
//! existing profile, `init_if_needed` finds it already initialised and skips
//! creation, and the handler overwrites the authority with their own key.

use anchor_lang::prelude::*;

declare_id!("Reg111111111111111111111111111111111111111");

#[program]
pub mod registry {
    use super::*;

    pub fn create_profile(ctx: Context<CreateProfile>, handle: String) -> Result<()> {
        let profile = &mut ctx.accounts.profile;
        profile.authority = ctx.accounts.payer.key();
        profile.handle = handle;
        profile.reputation = 0;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CreateProfile<'info> {
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
    pub reputation: u64,
}
