//! WT014 — remaining accounts used together with nothing relating them.
//!
//! This is TOB-DRIFT-8, "Missing verification of maker and maker_stats
//! accounts", reduced to its shape. Two accounts are pulled off the end of the
//! account list by hand, deserialised, and used together — and nothing checks
//! that they belong to the same user. A caller can pass one trader's `User`
//! with another trader's `UserStats`, and the fill is credited across the pair.
//!
//! This was a documented known gap until v1.1: every account-validation rule
//! started from `#[derive(Accounts)]`, and these accounts never appear in one.
//! The model now records accounts deserialised from `remaining_accounts`, and
//! WT014 asks whether two of them that both store an authority are ever
//! compared on it.

use anchor_lang::prelude::*;
use std::iter::Peekable;
use std::slice::Iter;

declare_id!("Rem111111111111111111111111111111111111111");

#[program]
pub mod remaining_accounts_gap {
    use super::*;

    pub fn place_and_take(ctx: Context<PlaceAndTake>, size: u64) -> Result<()> {
        let mut iter = ctx.remaining_accounts.iter().peekable();
        let (maker, maker_stats) = get_maker_and_maker_stats(&mut iter)?;

        // Nothing has established that these two describe the same trader.
        // A caller can pass one user's account and another user's statistics,
        // and the fill is credited across the pair.
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
    let maker_info = next_account_info(iter).map_err(|_| ErrorCode::MakerNotFound)?;
    let maker: AccountLoader<User> = AccountLoader::try_from(maker_info)?;

    let maker_stats_info = next_account_info(iter).map_err(|_| ErrorCode::MakerStatsNotFound)?;
    let maker_stats: AccountLoader<UserStats> = AccountLoader::try_from(maker_stats_info)?;

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

#[error_code]
pub enum ErrorCode {
    #[msg("maker not found")]
    MakerNotFound,
    #[msg("maker stats not found")]
    MakerStatsNotFound,
}
