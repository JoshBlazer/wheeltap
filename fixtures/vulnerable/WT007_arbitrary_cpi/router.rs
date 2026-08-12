//! WT007 — invoking a program the caller chose.
//!
//! `target_program` is an `AccountInfo`, so nothing pins which program it is.
//! The handler builds a CPI against it and signs with the vault PDA.
//!
//! An attacker passes their own program. It receives the invocation *with the
//! vault's signature attached*, and can do anything the vault is allowed to do.
//! The type `Program<'info, Token>` exists precisely to make this impossible:
//! it asserts the address before the handler runs.

use anchor_lang::prelude::*;

declare_id!("Rout111111111111111111111111111111111111111");

#[program]
pub mod router {
    use super::*;

    pub fn forward(ctx: Context<Forward>, amount: u64) -> Result<()> {
        let bump = ctx.bumps.vault_authority;
        let seeds: &[&[u8]] = &[b"vault-authority", &[bump]];

        let accounts = anchor_spl::token::Transfer {
            from: ctx.accounts.vault.to_account_info(),
            to: ctx.accounts.destination.to_account_info(),
            authority: ctx.accounts.vault_authority.to_account_info(),
        };

        anchor_spl::token::transfer(
            CpiContext::new_with_signer(
                ctx.accounts.target_program.to_account_info(),
                accounts,
                &[seeds],
            ),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct Forward<'info> {
    pub caller: Signer<'info>,

    /// CHECK: PDA signer for the vault
    #[account(seeds = [b"vault-authority"], bump)]
    pub vault_authority: UncheckedAccount<'info>,

    #[account(mut)]
    pub vault: Account<'info, anchor_spl::token::TokenAccount>,

    #[account(mut)]
    pub destination: Account<'info, anchor_spl::token::TokenAccount>,

    /// CHECK: the token program to call
    pub target_program: AccountInfo<'info>,
}
