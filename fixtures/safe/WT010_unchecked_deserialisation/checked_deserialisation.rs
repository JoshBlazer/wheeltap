//! WT010 safe — deserialisation that keeps the discriminator check.

use anchor_lang::prelude::*;

declare_id!("Chk211111111111111111111111111111111111111");

#[program]
pub mod safe_store {
    use super::*;

    /// The typed form does the check for you, before the handler runs.
    pub fn read_typed(ctx: Context<ReadTyped>) -> Result<()> {
        msg!("fee is {}", ctx.accounts.config.fee_bps);
        Ok(())
    }

    /// Manual deserialisation, but with the checking variant. The trailing
    /// `_unchecked` is the whole difference between this and the vulnerable
    /// fixture, which is exactly why the rule keys on it.
    pub fn read_manual(ctx: Context<ReadManual>) -> Result<()> {
        let mut data: &[u8] = &ctx.accounts.config.try_borrow_data()?;
        let config = Config::try_deserialize(&mut data)?;
        msg!("fee is {}", config.fee_bps);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct ReadTyped<'info> {
    pub caller: Signer<'info>,
    pub config: Account<'info, Config>,
}

#[derive(Accounts)]
pub struct ReadManual<'info> {
    pub caller: Signer<'info>,

    /// CHECK: owner pinned, discriminator checked by try_deserialize
    #[account(owner = crate::ID)]
    pub config: AccountInfo<'info>,
}

#[account]
pub struct Config {
    pub admin: Pubkey,
    pub fee_bps: u16,
}
