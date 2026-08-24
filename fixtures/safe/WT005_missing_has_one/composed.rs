//! WT005 safe — relationships enforced by composition rather than by one check.
//!
//! Found by the Phase 6 audit comparison. Drift enforces the link between a
//! `user`, its `user_stats`, and the `authority` that signs for it with two
//! helper predicates rather than one:
//!
//! ```ignore
//! constraint = can_sign_for_user(&user, &authority)?   // on user
//! constraint = is_stats_for_user(&user, &user_stats)?  // on user_stats
//! ```
//!
//! Neither constraint names both `user_stats` and `authority`, so a rule that
//! looks for a single constraint mentioning both reports `user_stats` as
//! unlinked — ten times across drift. The relationship holds transitively, and
//! it is exactly the relationship Trail of Bits asked drift to add
//! (TOB-DRIFT-8, "Missing verification of maker and maker_stats accounts").
//!
//! The second struct is the other spelling of the same idea: a sibling whose
//! address is *derived* from this account, which is a stronger guarantee than
//! any comparison and equally invisible to a single-constraint check.

use anchor_lang::prelude::*;

declare_id!("Cmp111111111111111111111111111111111111111");

#[program]
pub mod safe_composed {
    use super::*;

    pub fn place_order(ctx: Context<PlaceOrder>, size: u64) -> Result<()> {
        let mut stats = ctx.accounts.user_stats.load_mut()?;
        stats.orders_placed = stats.orders_placed.saturating_add(1);
        let mut user = ctx.accounts.user.load_mut()?;
        user.open_size = user.open_size.saturating_add(size);
        Ok(())
    }

    pub fn add_constituent(ctx: Context<AddConstituent>, weight: u64) -> Result<()> {
        let mut targets = ctx.accounts.constituent_target_base.load_mut()?;
        targets.total_weight = targets.total_weight.saturating_add(weight);
        Ok(())
    }
}

/// `user_stats` is tied to `authority` through `user`, in two steps.
#[derive(Accounts)]
pub struct PlaceOrder<'info> {
    pub state: Box<Account<'info, State>>,

    #[account(
        mut,
        constraint = can_sign_for_user(&user, &authority)?
    )]
    pub user: AccountLoader<'info, User>,

    #[account(
        mut,
        constraint = is_stats_for_user(&user, &user_stats)?
    )]
    pub user_stats: AccountLoader<'info, UserStats>,

    pub authority: Signer<'info>,
}

/// `lp_pool` is tied to `constituent_target_base` by derivation: the sibling's
/// address is a PDA of this account's key, so a mismatched pair cannot exist.
#[derive(Accounts)]
pub struct AddConstituent<'info> {
    #[account(mut)]
    pub lp_pool: AccountLoader<'info, LpPool>,

    #[account(
        mut,
        seeds = [b"constituent_target_base", lp_pool.key().as_ref()],
        bump = constituent_target_base.load()?.bump,
    )]
    pub constituent_target_base: AccountLoader<'info, ConstituentTargetBase>,

    #[account(mut)]
    pub admin: Signer<'info>,
}

/// Both predicates are ordinary functions, which is the whole point: the
/// assertion is one call away from anything a syntactic analyser can read.
pub fn can_sign_for_user(
    user: &AccountLoader<User>,
    authority: &Signer,
) -> Result<bool> {
    Ok(user.load()?.authority == authority.key())
}

pub fn is_stats_for_user(
    user: &AccountLoader<User>,
    user_stats: &AccountLoader<UserStats>,
) -> Result<bool> {
    Ok(user.load()?.authority == user_stats.load()?.authority)
}

#[account(zero_copy)]
pub struct User {
    pub authority: Pubkey,
    pub open_size: u64,
}

#[account(zero_copy)]
pub struct UserStats {
    pub authority: Pubkey,
    pub orders_placed: u64,
}

#[account(zero_copy)]
pub struct LpPool {
    pub constituent_target_base: Pubkey,
}

#[account(zero_copy)]
pub struct ConstituentTargetBase {
    pub lp_pool: Pubkey,
    pub total_weight: u64,
    pub bump: u8,
}

#[account]
pub struct State {
    pub admin: Pubkey,
}
