//! WT013 safe — accounts used in places a handler-body search does not look.
//!
//! - `Deposit` keeps its logic in an `impl` on the Accounts struct, called as
//!   `ctx.accounts.deposit(amount)`. The fields are used through `self`.
//! - `Swap` destructures its accounts, and `Settle` takes an alias to them;
//!   the fields are used under names the handler chose.
//! - `Rebalance` hands its whole account list to a helper. What the helper
//!   does with it cannot be seen from the handler, so nothing may be reported.
//! - `Sweep` is an entrypoint delegating to a `handle_*` function, the shape
//!   most production programs use. The use is in the delegate.

use anchor_lang::prelude::*;

declare_id!("Out111111111111111111111111111111111111111");

#[program]
pub mod out_of_sight {
    use super::*;

    pub fn deposit(ctx: Context<Deposit>, quantity: u64) -> Result<()> {
        ctx.accounts.deposit(quantity)
    }

    pub fn swap(ctx: Context<Swap>, quantity: u64) -> Result<()> {
        let Swap { trader, book, .. } = ctx.accounts;
        require_keys_eq!(book.trader, trader.key());
        book.filled = book.filled.checked_add(quantity).ok_or(BookError::Overflow)?;
        Ok(())
    }

    pub fn settle(ctx: Context<Settle>) -> Result<()> {
        let accounts = &mut ctx.accounts;
        require_keys_eq!(accounts.book.trader, accounts.trader.key());
        accounts.book.filled = 0;
        Ok(())
    }

    pub fn rebalance(ctx: Context<Rebalance>, target: u64) -> Result<()> {
        apply_rebalance(&mut ctx.accounts, target)
    }

    pub fn sweep(ctx: Context<Sweep>) -> Result<()> {
        handle_sweep(ctx)
    }
}

pub fn handle_sweep(ctx: Context<Sweep>) -> Result<()> {
    require_keys_eq!(ctx.accounts.book.trader, ctx.accounts.trader.key());
    ctx.accounts.book.filled = 0;
    Ok(())
}

fn apply_rebalance(accounts: &mut Rebalance, target: u64) -> Result<()> {
    msg!("rebalance requested by {}", accounts.keeper.key());
    accounts.plan.target = target;
    Ok(())
}

#[derive(Accounts)]
pub struct Deposit<'info> {
    pub trader: Signer<'info>,

    #[account(mut, has_one = trader)]
    pub book: Account<'info, Book>,
}

impl<'info> Deposit<'info> {
    pub fn deposit(&mut self, quantity: u64) -> Result<()> {
        self.book.filled = self.book.filled.checked_add(quantity).ok_or(BookError::Overflow)?;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Swap<'info> {
    pub trader: Signer<'info>,

    #[account(mut)]
    pub book: Account<'info, Book>,
}

#[derive(Accounts)]
pub struct Settle<'info> {
    pub trader: Signer<'info>,

    #[account(mut)]
    pub book: Account<'info, Book>,
}

#[derive(Accounts)]
pub struct Rebalance<'info> {
    pub keeper: Signer<'info>,

    #[account(mut, seeds = [b"plan"], bump = plan.bump)]
    pub plan: Account<'info, Plan>,
}

#[derive(Accounts)]
pub struct Sweep<'info> {
    pub trader: Signer<'info>,

    #[account(mut)]
    pub book: Account<'info, Book>,
}

#[account]
pub struct Book {
    pub trader: Pubkey,
    pub filled: u64,
}

#[account]
pub struct Plan {
    pub target: u64,
    pub bump: u8,
}

#[error_code]
pub enum BookError {
    #[msg("overflow")]
    Overflow,
}
