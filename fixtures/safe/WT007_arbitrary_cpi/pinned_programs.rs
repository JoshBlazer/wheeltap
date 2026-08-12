//! WT007 safe — CPI targets that are pinned, and account lists that hold
//! program accounts without calling them.

use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use anchor_spl::token_interface::TokenInterface;

declare_id!("Pin111111111111111111111111111111111111111");

pub mod metadata_program {
    use anchor_lang::prelude::*;
    declare_id!("metaqbxxUerdq28cj1RbAWkYQm3ybzjb6a8bt518x1s");
}

#[program]
pub mod safe_router {
    use super::*;

    /// The typed form. `Program<'info, Token>` asserts the address before the
    /// handler runs, which is what makes this safe.
    pub fn forward_typed(ctx: Context<ForwardTyped>, amount: u64) -> Result<()> {
        token::transfer(
            CpiContext::new(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.vault.to_account_info(),
                    to: ctx.accounts.destination.to_account_info(),
                    authority: ctx.accounts.owner.to_account_info(),
                },
                ),
            amount,
        )
    }

    /// An `Interface` accepts several known token programs and no others —
    /// Token and Token-2022 — which is the standard way to support both.
    pub fn forward_interface(ctx: Context<ForwardInterface>, amount: u64) -> Result<()> {
        msg!("would transfer {} via {}", amount, ctx.accounts.token_program.key());
        Ok(())
    }

    /// An `AccountInfo` program whose address is pinned by constraint. Some
    /// programs have no Anchor type available and this is the remaining option.
    pub fn forward_pinned(ctx: Context<ForwardPinned>) -> Result<()> {
        msg!("metadata program: {}", ctx.accounts.metadata_program.key());
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ForwardTyped<'info> {
    pub owner: Signer<'info>,
    #[account(mut)]
    pub vault: Account<'info, TokenAccount>,
    #[account(mut)]
    pub destination: Account<'info, TokenAccount>,
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct ForwardInterface<'info> {
    pub owner: Signer<'info>,
    pub token_program: Interface<'info, TokenInterface>,
}

#[derive(Accounts)]
pub struct ForwardPinned<'info> {
    pub owner: Signer<'info>,

    /// CHECK: address pinned to the metadata program
    #[account(address = metadata_program::ID)]
    pub metadata_program: AccountInfo<'info>,
}
