//! WT002 safe — unchecked accounts whose owner *is* established, and
//! unchecked accounts whose data is never read.
//!
//! Three shapes here, and a naive "AccountInfo plus a data read" rule flags at
//! least two of them.

use anchor_lang::prelude::*;
use anchor_spl::token::{Token, TokenAccount};

declare_id!("Owner11111111111111111111111111111111111111");

pub mod pyth_oracle {
    use anchor_lang::prelude::*;
    declare_id!("FsJ3A3u2vn5cTVofAjvy6y5kwABJAqYWpe4975bi2epH");
}

#[program]
pub mod safe_lending {
    use super::*;

    /// The owning program is pinned by constraint, so the bytes can be trusted.
    pub fn borrow_with_owner_check(ctx: Context<BorrowOwnerChecked>, amount: u64) -> Result<()> {
        let data = ctx.accounts.oracle.try_borrow_data()?;
        let feed = PriceFeed::try_from_slice(&data)?;
        ctx.accounts.position.borrowed = ctx
            .accounts
            .position
            .borrowed
            .saturating_add(amount / feed.price.max(1));
        Ok(())
    }

    /// The address is pinned outright, which is stricter still.
    pub fn borrow_with_address_check(ctx: Context<BorrowAddressChecked>, amount: u64) -> Result<()> {
        let data = ctx.accounts.oracle.try_borrow_data()?;
        let feed = PriceFeed::try_from_slice(&data)?;
        ctx.accounts.position.borrowed = ctx
            .accounts
            .position
            .borrowed
            .saturating_add(amount / feed.price.max(1));
        Ok(())
    }

    /// Nothing here reads account *data*. The accounts are handed to a CPI,
    /// which is the overwhelmingly common reason to hold an `AccountInfo` at
    /// all. Flagging this would flag most real Anchor programs.
    pub fn forward_to_cpi(ctx: Context<ForwardToCpi>, amount: u64) -> Result<()> {
        let accounts = anchor_spl::token::Transfer {
            from: ctx.accounts.source.to_account_info(),
            to: ctx.accounts.destination.to_account_info(),
            authority: ctx.accounts.authority.to_account_info(),
        };
        anchor_spl::token::transfer(
            CpiContext::new(ctx.accounts.token_program.to_account_info(), accounts),
            amount,
        )
    }
}

#[derive(Accounts)]
pub struct BorrowOwnerChecked<'info> {
    #[account(mut, has_one = owner)]
    pub position: Account<'info, Position>,
    pub owner: Signer<'info>,

    /// CHECK: owner pinned to the oracle program below
    #[account(owner = pyth_oracle::ID)]
    pub oracle: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct BorrowAddressChecked<'info> {
    #[account(mut, has_one = owner)]
    pub position: Account<'info, Position>,
    pub owner: Signer<'info>,

    /// CHECK: this exact feed account and no other
    #[account(address = pyth_oracle::ID)]
    pub oracle: AccountInfo<'info>,
}

#[derive(Accounts)]
pub struct ForwardToCpi<'info> {
    pub authority: Signer<'info>,

    #[account(mut)]
    pub source: Account<'info, TokenAccount>,

    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,

    pub token_program: Program<'info, Token>,
}

#[derive(AnchorSerialize, AnchorDeserialize)]
pub struct PriceFeed {
    pub price: u64,
    pub published_at: i64,
}

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub collateral: u64,
    pub borrowed: u64,
}
