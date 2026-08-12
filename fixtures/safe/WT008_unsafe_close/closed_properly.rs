//! WT008 safe — closing an account correctly, both ways.

use anchor_lang::prelude::*;

declare_id!("Clsd111111111111111111111111111111111111111");

#[program]
pub mod safe_closer {
    use super::*;

    /// The idiomatic way. Anchor drains the lamports, zeroes the data, and
    /// assigns the account to the system program.
    pub fn close_with_constraint(_ctx: Context<CloseWithConstraint>) -> Result<()> {
        Ok(())
    }

    /// By hand, done properly: the data is zeroed and the account reassigned,
    /// so reviving it recovers nothing.
    pub fn close_manually(ctx: Context<CloseManually>) -> Result<()> {
        let position = ctx.accounts.position.to_account_info();
        let destination = ctx.accounts.owner.to_account_info();

        let balance = position.lamports();
        **destination.try_borrow_mut_lamports()? += balance;
        **position.try_borrow_mut_lamports()? = 0;

        position.assign(&anchor_lang::system_program::ID);
        position.realloc(0, false)?;

        Ok(())
    }

    /// Moving lamports is not closing anything. A rule that flags every write
    /// to `lamports` flags every program that pays anyone.
    pub fn pay_out(ctx: Context<PayOut>, amount: u64) -> Result<()> {
        **ctx.accounts.treasury.to_account_info().try_borrow_mut_lamports()? -= amount;
        **ctx.accounts.recipient.try_borrow_mut_lamports()? += amount;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct CloseWithConstraint<'info> {
    #[account(mut, has_one = owner, close = owner)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseManually<'info> {
    #[account(mut, has_one = owner)]
    pub position: Account<'info, Position>,
    #[account(mut)]
    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct PayOut<'info> {
    #[account(mut, has_one = owner)]
    pub treasury: Account<'info, Position>,
    #[account(mut)]
    pub owner: Signer<'info>,
    /// CHECK: destination for the payment
    #[account(mut)]
    pub recipient: AccountInfo<'info>,
}

#[account]
pub struct Position {
    pub owner: Pubkey,
    pub size: u64,
}
