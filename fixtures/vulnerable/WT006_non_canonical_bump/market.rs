//! WT006 — a PDA bump taken from instruction data.
//!
//! `find_program_address` returns the *canonical* bump: the highest byte that
//! yields an address off the ed25519 curve. It is not the only one that works.
//! Several bumps typically produce valid, distinct PDAs for the same seeds.
//!
//! Taking the bump from the caller means the caller chooses which of those
//! addresses to use. They can create a second, third, fourth market for the
//! same seeds — each passing every constraint, each with its own state, none of
//! them the one the program's other instructions will look up.
//!
//! Writing `bump` alone lets Anchor supply the canonical one.

use anchor_lang::prelude::*;

declare_id!("Mkt111111111111111111111111111111111111111");

#[program]
pub mod market {
    use super::*;

    pub fn open_market(ctx: Context<OpenMarket>, market_bump: u8, fee_bps: u16) -> Result<()> {
        let market = &mut ctx.accounts.market;
        market.bump = market_bump;
        market.fee_bps = fee_bps;
        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(market_bump: u8)]
pub struct OpenMarket<'info> {
    #[account(
        init,
        payer = creator,
        space = 8 + Market::INIT_SPACE,
        seeds = [b"market", creator.key().as_ref()],
        bump = market_bump,
    )]
    pub market: Account<'info, Market>,

    #[account(mut)]
    pub creator: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
pub struct Market {
    pub bump: u8,
    pub fee_bps: u16,
}
