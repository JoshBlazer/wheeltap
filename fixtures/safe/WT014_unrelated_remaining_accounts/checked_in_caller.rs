//! WT014 safe — the relationship is checked by the caller.
//!
//! This is drift's own referrer handling. The helper loads a `User` and a
//! `UserStats` off the remaining accounts and checks nothing about them; the
//! handler that calls it compares their authorities before using either. A
//! rule that read only the helper would report correct code, and the helper is
//! where every reviewer would look first.

use anchor_lang::prelude::*;
use std::iter::Peekable;
use std::slice::Iter;

declare_id!("Ref111111111111111111111111111111111111111");

#[program]
pub mod referrals {
    use super::*;

    pub fn register(ctx: Context<Register>) -> Result<()> {
        let iter = &mut ctx.remaining_accounts.iter().peekable();
        let (referrer, referrer_stats) = get_referrer_and_referrer_stats(iter)?;

        let referrer = referrer.load()?;
        let mut referrer_stats = referrer_stats.load_mut()?;
        require!(
            referrer.authority == referrer_stats.authority,
            ReferralError::AuthorityMismatch
        );

        referrer_stats.referrals = referrer_stats.referrals.saturating_add(1);
        ctx.accounts.profile.referrer = referrer.authority;
        Ok(())
    }
}

fn get_referrer_and_referrer_stats<'a>(
    iter: &mut Peekable<Iter<'a, AccountInfo<'a>>>,
) -> Result<(AccountLoader<'a, User>, AccountLoader<'a, UserStats>)> {
    let referrer_info = next_account_info(iter)?;
    let referrer: AccountLoader<User> = AccountLoader::try_from(referrer_info)?;

    let referrer_stats_info = next_account_info(iter)?;
    let referrer_stats: AccountLoader<UserStats> = AccountLoader::try_from(referrer_stats_info)?;

    Ok((referrer, referrer_stats))
}

#[derive(Accounts)]
pub struct Register<'info> {
    pub authority: Signer<'info>,

    #[account(mut, has_one = authority)]
    pub profile: Account<'info, Profile>,
}

#[account]
pub struct Profile {
    pub authority: Pubkey,
    pub referrer: Pubkey,
}

#[account(zero_copy)]
pub struct User {
    pub authority: Pubkey,
}

#[account(zero_copy)]
pub struct UserStats {
    pub authority: Pubkey,
    pub referrals: u64,
}

#[error_code]
pub enum ReferralError {
    #[msg("referrer and referrer stats belong to different users")]
    AuthorityMismatch,
}
