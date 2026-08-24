//! WT011 safe — two accounts distinguished through the accounts they belong to.
//!
//! Found by the Phase 6 audit comparison. Drift's liquidation instructions take
//! a `liquidator`/`liquidator_stats` pair and a `user`/`user_stats` pair, and
//! reject self-liquidation in the handler:
//!
//! ```ignore
//! validate!(user_key != liquidator_key, ErrorCode::UserCantLiquidateThemself)?;
//! ```
//!
//! The comparison is between the two `User` accounts. The two `UserStats`
//! accounts are never compared — they do not have to be, because each is tied
//! by a constraint to the `User` it belongs to. If the users differ, so do
//! their statistics.
//!
//! A rule that looks for a comparison between the two accounts it flagged sees
//! nothing here and reports the pair, as it did on four of drift's
//! instructions.

use anchor_lang::prelude::*;

declare_id!("Dup111111111111111111111111111111111111111");

#[program]
pub mod safe_via_owners {
    use super::*;

    pub fn liquidate(ctx: Context<Liquidate>, amount: u64) -> Result<()> {
        let user_key = ctx.accounts.user.key();
        let liquidator_key = ctx.accounts.liquidator.key();

        // The pair that matters is compared. The stats accounts follow.
        require!(user_key != liquidator_key, LiquidateError::CannotLiquidateSelf);

        let mut user = ctx.accounts.user.load_mut()?;
        user.collateral = user.collateral.saturating_sub(amount);
        let mut liquidator = ctx.accounts.liquidator.load_mut()?;
        liquidator.collateral = liquidator.collateral.saturating_add(amount);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Liquidate<'info> {
    pub authority: Signer<'info>,

    #[account(mut, constraint = can_sign_for_user(&liquidator, &authority)?)]
    pub liquidator: AccountLoader<'info, User>,

    #[account(mut, constraint = is_stats_for_user(&liquidator, &liquidator_stats)?)]
    pub liquidator_stats: AccountLoader<'info, UserStats>,

    #[account(mut)]
    pub user: AccountLoader<'info, User>,

    #[account(mut, constraint = is_stats_for_user(&user, &user_stats)?)]
    pub user_stats: AccountLoader<'info, UserStats>,
}

pub fn can_sign_for_user(user: &AccountLoader<User>, authority: &Signer) -> Result<bool> {
    Ok(user.load()?.authority == authority.key())
}

pub fn is_stats_for_user(
    user: &AccountLoader<User>,
    stats: &AccountLoader<UserStats>,
) -> Result<bool> {
    Ok(user.load()?.authority == stats.load()?.authority)
}

#[account(zero_copy)]
pub struct User {
    pub authority: Pubkey,
    pub collateral: u64,
}

#[account(zero_copy)]
pub struct UserStats {
    pub authority: Pubkey,
    pub liquidations: u64,
}

#[error_code]
pub enum LiquidateError {
    #[msg("a user cannot liquidate themself")]
    CannotLiquidateSelf,
}
