//! WT012 — allocating inside a loop.
//!
//! Compute units are a hard per-transaction budget on Solana, and heap
//! allocation is expensive relative to almost everything else a program does.
//! Cloning a vector on every iteration turns a linear pass into a quadratic
//! one, and a program that fits the budget in testing stops fitting it when the
//! account grows.
//!
//! This is hygiene rather than a vulnerability, which is why it is Low.

use anchor_lang::prelude::*;

declare_id!("Alloc11111111111111111111111111111111111111");

#[program]
pub mod rebalance {
    use super::*;

    pub fn rebalance(ctx: Context<Rebalance>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;

        for index in 0..pool.weights.len() {
            let snapshot = pool.weights.clone();
            let total: u64 = snapshot.iter().sum();
            pool.weights[index] = pool.weights[index] * 100 / total.max(1);
        }

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
