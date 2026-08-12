//! WT012 safe — the same work with the allocation hoisted, and cheap
//! per-iteration operations that are not allocations.

use anchor_lang::prelude::*;

declare_id!("Hst111111111111111111111111111111111111111");

#[program]
pub mod safe_rebalance {
    use super::*;

    /// The clone happens once, outside the loop.
    pub fn rebalance(ctx: Context<Rebalance>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        let snapshot = pool.weights.clone();
        let total: u64 = snapshot.iter().sum();

        for index in 0..pool.weights.len() {
            pool.weights[index] = snapshot[index] * 100 / total.max(1);
        }

        Ok(())
    }

    /// Copying a `Pubkey` or an integer inside a loop is not a heap
    /// allocation. A rule that flags every `.clone()` in a loop body flags this.
    pub fn tally(ctx: Context<Rebalance>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        let mut seen = 0u64;

        for weight in &pool.weights {
            let owner = pool.owner;
            if owner != Pubkey::default() {
                seen += *weight;
            }
        }

        msg!("total {}", seen);
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Rebalance<'info> {
    #[account(mut, has_one = owner)]
    pub pool: Account<'info, Pool>,
    pub owner: Signer<'info>,
}

#[account]
pub struct Pool {
    pub owner: Pubkey,
    pub weights: Vec<u64>,
}
