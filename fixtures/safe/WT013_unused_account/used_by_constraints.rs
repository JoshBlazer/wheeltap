//! WT013 safe — accounts whose only use is in the constraints.
//!
//! None of `payer`, `authority`, `mint`, or `config` is mentioned by the
//! handler, and a rule that read only handler bodies would report all four.
//! Each one is doing work all the same, because Anchor does it on the
//! handler's behalf before the handler runs:
//!
//! - `payer` funds the `init` through `payer = payer`;
//! - `authority` is tied to the pool through `has_one = authority`;
//! - `mint` is checked against the new token account through `token::mint`;
//! - `config` supplies a seed and a stored bump to other accounts.
//!
//! `Pause` holds the remaining two shapes. `settings` is never read by name
//! outside its own constraints but is written by the handler; `admin` is a
//! signer pinned to a fixed address, which is a complete gate on its own.
//! Programs and sysvars are left unused routinely, because Anchor needs them
//! for `init` and CPI rather than the handler.

use anchor_lang::prelude::*;
use anchor_spl::token::{Mint, Token, TokenAccount};

declare_id!("Con111111111111111111111111111111111111111");

pub const ADMIN: Pubkey = pubkey!("Adm1n11111111111111111111111111111111111111");

#[program]
pub mod pool_admin {
    use super::*;

    pub fn open_vault(ctx: Context<OpenVault>) -> Result<()> {
        ctx.accounts.pool.vault = ctx.accounts.vault.key();
        Ok(())
    }

    pub fn pause(ctx: Context<Pause>) -> Result<()> {
        ctx.accounts.settings.paused = true;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct OpenVault<'info> {
    #[account(mut)]
    pub payer: Signer<'info>,

    pub authority: Signer<'info>,

    #[account(mut, has_one = authority, seeds = [b"pool", config.key().as_ref()], bump = pool.bump)]
    pub pool: Account<'info, Pool>,

    #[account(seeds = [b"config"], bump = config.bump)]
    pub config: Account<'info, Config>,

    pub mint: Account<'info, Mint>,

    #[account(init, payer = payer, token::mint = mint, token::authority = pool)]
    pub vault: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
    pub system_program: Program<'info, System>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct Pause<'info> {
    #[account(address = ADMIN)]
    pub admin: Signer<'info>,

    #[account(mut, seeds = [b"settings"], bump = settings.bump)]
    pub settings: Account<'info, Settings>,
}

#[account]
pub struct Pool {
    pub authority: Pubkey,
    pub vault: Pubkey,
    pub bump: u8,
}

#[account]
pub struct Config {
    pub bump: u8,
}

#[account]
pub struct Settings {
    pub paused: bool,
    pub bump: u8,
}
