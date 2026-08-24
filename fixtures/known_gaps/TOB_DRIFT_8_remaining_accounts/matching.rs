//! Known gap — accounts taken from `remaining_accounts` are not modelled.
//!
//! This is TOB-DRIFT-8, "Missing verification of maker and maker_stats
//! accounts", reduced to its shape. Two accounts are pulled off the end of the
//! account list by hand, deserialised, and used together — and nothing checks
//! that they belong to the same user.
//!
//! Wheeltap reports nothing here, and would have reported nothing on drift's
//! real code: `fixtures/corpus/drift` is a fixed version, but scanning the
//! pre-fix `optional_accounts.rs` and `user.rs` at
//! `8e4f15771cce51f6c74628c19b74c5e83c51ed69` also yields zero findings. The
//! silence is structural, not incidental.
//!
//! **Why it is missed.** Every detector that reasons about account validation
//! starts from `#[derive(Accounts)]`. These accounts never appear in one. They
//! arrive through `ctx.remaining_accounts`, which is Anchor's escape hatch from
//! the declarative model, and with it goes every constraint the model is built
//! to read.
//!
//! **What catching it would need.** A separate analysis keyed on
//! `next_account_info` and `remaining_accounts`: track each account pulled from
//! the iterator, note the type it is deserialised into, and ask whether
//! anything relates them before use. That is a different rule from WT005, not a
//! widening of it — the evidence lives in statements rather than in attributes.

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
