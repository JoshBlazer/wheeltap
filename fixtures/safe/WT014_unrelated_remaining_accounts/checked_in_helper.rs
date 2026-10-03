//! WT014 safe — the helper relates the accounts before returning them.
//!
//! The same maker and maker-stats pair as the vulnerable fixture, with the one
//! line that fixes it: `require_keys_eq!` on the two stored authorities. The
//! comparison lives inside a macro, which an expression visitor would not walk
//! into.

use anchor_lang::prelude::*;
use std::iter::Peekable;
use std::slice::Iter;

declare_id!("Hlp111111111111111111111111111111111111111");

#[program]
pub mod matching_checked {
    use super::*;

    pub fn place_and_take(ctx: Context<PlaceAndTake>, size: u64) -> Result<()> {
        let mut iter = ctx.remaining_accounts.iter().peekable();
        let (maker, maker_stats) = get_maker_and_maker_stats(&mut iter)?;

        let mut maker = maker.load_mut()?;
        let mut maker_stats = maker_stats.load_mut()?;
        maker.open_size = maker.open_size.saturating_sub(size);
        maker_stats.volume = maker_stats.volume.saturating_add(size);
        Ok(())
    }
}

fn get_maker_and_maker_stats<'a>(
    iter: &mut Peekable<Iter<'a, AccountInfo<'a>>>,
) -> Result<(AccountLoader<'a, User>, AccountLoader<'a, UserStats>)> {
    let maker_info = next_account_info(iter)?;
    let maker = AccountLoader::<User>::try_from(maker_info)?;

    let maker_stats_info = next_account_info(iter)?;
    let maker_stats = AccountLoader::<UserStats>::try_from(maker_stats_info)?;

    require_keys_eq!(maker.load()?.authority, maker_stats.load()?.authority);

    Ok((maker, maker_stats))
}

#[derive(Accounts)]
pub struct PlaceAndTake<'info> {
    #[account(mut, constraint = user.load()?.authority == authority.key())]
    pub user: AccountLoader<'info, User>,
    pub authority: Signer<'info>,
}

#[account(zero_copy)]
pub struct User {
    pub authority: Pubkey,
    pub open_size: u64,
}

#[account(zero_copy)]
pub struct UserStats {
    pub authority: Pubkey,
    pub volume: u64,
}
