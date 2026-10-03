//! WT014 safe — remaining accounts that are not a related pair.
//!
//! - `load_maps` walks every remaining account and files each into a map keyed
//!   by its authority. Users and statistics are matched up by that key when
//!   they are used, so there is no fixed pair for a caller to mismatch.
//! - `settle_market` loads a `Market` and a `Vault` that both store a `mint`.
//!   Sharing a key field is not a claim that the two accounts belong together
//!   by owner, and only authority-like fields are read as one. Matching on
//!   every shared `Pubkey` would report half of any real protocol.

use anchor_lang::prelude::*;
use std::collections::BTreeMap;

declare_id!("Col111111111111111111111111111111111111111");

#[program]
pub mod collections {
    use super::*;

    pub fn crank(ctx: Context<Crank>) -> Result<()> {
        let (users, stats) = load_maps(ctx.remaining_accounts)?;
        for (authority, user) in &users {
            if let Some(stat) = stats.get(authority) {
                msg!("{} {}", user.key(), stat.key());
            }
        }
        ctx.accounts.clock_state.cranks = ctx.accounts.clock_state.cranks.saturating_add(1);
        Ok(())
    }

    pub fn settle_market(ctx: Context<Crank>) -> Result<()> {
        let iter = &mut ctx.remaining_accounts.iter();
        let market_info = next_account_info(iter)?;
        let market: AccountLoader<Market> = AccountLoader::try_from(market_info)?;
        let vault_info = next_account_info(iter)?;
        let vault: AccountLoader<Vault> = AccountLoader::try_from(vault_info)?;

        msg!("{} {}", market.key(), vault.key());
        ctx.accounts.clock_state.cranks = ctx.accounts.clock_state.cranks.saturating_add(1);
        Ok(())
    }
}

#[allow(clippy::type_complexity)]
fn load_maps<'a>(
    accounts: &'a [AccountInfo<'a>],
) -> Result<(
    BTreeMap<Pubkey, AccountLoader<'a, User>>,
    BTreeMap<Pubkey, AccountLoader<'a, UserStats>>,
)> {
    let mut users = BTreeMap::new();
    let mut stats = BTreeMap::new();
    for info in accounts {
        if let Ok(user) = AccountLoader::<User>::try_from(info) {
            let authority = user.load()?.authority;
            users.insert(authority, user);
            continue;
        }
        let stat: AccountLoader<UserStats> = AccountLoader::try_from(info)?;
        let authority = stat.load()?.authority;
        stats.insert(authority, stat);
    }
    Ok((users, stats))
}

#[derive(Accounts)]
pub struct Crank<'info> {
    pub keeper: Signer<'info>,

    #[account(mut, seeds = [b"clock"], bump = clock_state.bump)]
    pub clock_state: Account<'info, ClockState>,
}

#[account]
pub struct ClockState {
    pub cranks: u64,
    pub bump: u8,
}

#[account(zero_copy)]
pub struct User {
    pub authority: Pubkey,
}

#[account(zero_copy)]
pub struct UserStats {
    pub authority: Pubkey,
}

#[account(zero_copy)]
pub struct Market {
    pub mint: Pubkey,
}

#[account(zero_copy)]
pub struct Vault {
    pub mint: Pubkey,
}
