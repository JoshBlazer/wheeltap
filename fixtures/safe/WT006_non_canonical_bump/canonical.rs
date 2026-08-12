//! WT006 safe — canonical bumps, and the stored-bump idiom.
//!
//! The second case is the one that matters. `bump = market.bump` is *not*
//! instruction data: it reads the bump the program itself stored at creation
//! time, when Anchor supplied the canonical one. Re-deriving from storage is
//! both correct and cheaper than recomputing `find_program_address`, and it is
//! everywhere in real programs — escrow does it, drift does it 147 times.
//!
//! A rule that flags every `bump = expr` flags all of them.

use anchor_lang::prelude::*;

declare_id!("Can111111111111111111111111111111111111111");

#[program]
pub mod safe_market {
    use super::*;

    /// Creation: Anchor derives the canonical bump and hands it to us.
    pub fn open_market(ctx: Context<OpenMarket>, fee_bps: u16) -> Result<()> {
        let market = &mut ctx.accounts.market;
        market.bump = ctx.bumps.market;
        market.fee_bps = fee_bps;
        Ok(())
    }

    /// Later instructions re-derive using the stored bump.
    pub fn set_fee(ctx: Context<SetFee>, fee_bps: u16) -> Result<()> {
        ctx.accounts.market.fee_bps = fee_bps;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct OpenMarket<'info> {
    #[account(
        init,
        payer = creator,
        space = 8 + Market::INIT_SPACE,
        seeds = [b"market", creator.key().as_ref()],
        bump,
    )]
    pub market: Account<'info, Market>,

    #[account(mut)]
    pub creator: Signer<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct SetFee<'info> {
    #[account(
        mut,
        has_one = creator,
        seeds = [b"market", creator.key().as_ref()],
        bump = market.bump,
    )]
    pub market: Account<'info, Market>,

    pub creator: Signer<'info>,
}

#[account]
pub struct Market {
    pub creator: Pubkey,
    pub bump: u8,
    pub fee_bps: u16,
}
