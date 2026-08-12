//! WT001 safe — a PDA authority, which must *not* be a signer.
//!
//! This is the false positive that matters most, and the one a name-based
//! implementation walks straight into.
//!
//! `vault_authority` is named like an authority, typed `UncheckedAccount`, and
//! never asserted as a signer. A naive rule flags it immediately. But it is a
//! program-derived address: no private key exists for it, so no user *can*
//! sign for it. The program signs on its behalf with `CpiContext::new_with_signer`
//! and the derivation seeds. Demanding `Signer<'info>` here would not harden the
//! program — it would make it impossible to run.
//!
//! The distinguishing signal is structural, not lexical: the account carries
//! `seeds` and a canonical `bump`, so the runtime already proves the address is
//! one this program derived.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};

declare_id!("Pda111111111111111111111111111111111111111");

#[program]
pub mod pda_vault {
    use super::*;

    pub fn release(ctx: Context<Release>, amount: u64) -> Result<()> {
        let bump = ctx.bumps.vault_authority;
        let seeds: &[&[u8]] = &[b"vault-authority", &[bump]];
        let signer_seeds = &[seeds];

        token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.recipient.to_account_info(),
                    authority: ctx.accounts.vault_authority.to_account_info(),
                },
                signer_seeds,
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct Release<'info> {
    pub beneficiary: Signer<'info>,

    /// CHECK: PDA signed for by this program; no key exists for it
    #[account(seeds = [b"vault-authority"], bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,

    #[account(mut)]
    pub recipient: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}
