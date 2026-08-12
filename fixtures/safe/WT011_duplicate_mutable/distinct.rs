//! WT011 safe — accounts that cannot alias, and accounts where aliasing is
//! harmless.

use anchor_lang::prelude::*;

declare_id!("Dst111111111111111111111111111111111111111");

#[program]
pub mod safe_ledger {
    use super::*;

    /// The fix: assert that the two are different accounts.
    pub fn transfer(ctx: Context<Transfer>, amount: u64) -> Result<()> {
        ctx.accounts.from.balance = ctx.accounts.from.balance.saturating_sub(amount);
        ctx.accounts.to.balance = ctx.accounts.to.balance.saturating_add(amount);
        Ok(())
    }

    /// Two accounts of the same type where only one is written. Aliasing them
    /// changes nothing, and a rule keyed purely on "same type twice" flags it.
    pub fn record_from_template(ctx: Context<RecordFromTemplate>) -> Result<()> {
        ctx.accounts.target.balance = ctx.accounts.template.balance;
        Ok(())
    }

    /// Different account types entirely.
    pub fn settle(ctx: Context<Settle>) -> Result<()> {
        ctx.accounts.balance.balance = 0;
        ctx.accounts.log.entries += 1;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Transfer<'info> {
    #[account(mut, has_one = owner, constraint = from.key() != to.key() @ LedgerError::SameAccount)]
    pub from: Account<'info, Balance>,

    #[account(mut)]
    pub to: Account<'info, Balance>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct RecordFromTemplate<'info> {
    #[account(mut, has_one = owner)]
    pub target: Account<'info, Balance>,

    /// Read only, so aliasing is harmless.
    pub template: Account<'info, Balance>,

    pub owner: Signer<'info>,
}

#[derive(Accounts)]
pub struct Settle<'info> {
    #[account(mut, has_one = owner)]
    pub balance: Account<'info, Balance>,

    #[account(mut)]
    pub log: Account<'info, Log>,

    pub owner: Signer<'info>,
}

#[account]
pub struct Balance {
    pub owner: Pubkey,
    pub balance: u64,
}

#[account]
pub struct Log {
    pub entries: u64,
}

#[error_code]
pub enum LedgerError {
    #[msg("source and destination must differ")]
    SameAccount,
}
