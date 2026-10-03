//! WT013 — TOB-DRIFT-18, reduced to its shape.
//!
//! `Initialize` declares `program_signer`, and the handler never reads it. It
//! derives a *local* with the same name instead, which is exactly what makes
//! the account easy to miss in review: the name appears in the handler, the
//! account does not. Trail of Bits reported this against drift as
//! Informational, and it is still live in the scanned commit.
//!
//! An unused account is not an exploit on its own. It is a claim in the
//! interface — "this instruction needs the program signer" — that the code
//! does not honour, and callers and auditors both reason from the interface.

use anchor_lang::prelude::*;

declare_id!("Ini111111111111111111111111111111111111111");

#[program]
pub mod exchange {
    use super::*;

    pub fn initialize(ctx: Context<Initialize>) -> Result<()> {
        let (program_signer, program_signer_nonce) =
            Pubkey::find_program_address(&[b"program_signer".as_ref()], ctx.program_id);

        let state = &mut ctx.accounts.state;
        state.admin = ctx.accounts.admin.key();
        state.signer = program_signer;
        state.signer_nonce = program_signer_nonce;
        Ok(())
    }
}

#[derive(Accounts)]
pub struct Initialize<'info> {
    #[account(mut)]
    pub admin: Signer<'info>,

    #[account(init, seeds = [b"state"], bump, payer = admin, space = 8 + State::INIT_SPACE)]
    pub state: Account<'info, State>,

    /// CHECK: checked in `initialize`
    pub program_signer: AccountInfo<'info>,

    pub system_program: Program<'info, System>,
}

#[account]
#[derive(InitSpace)]
pub struct State {
    pub admin: Pubkey,
    pub signer: Pubkey,
    pub signer_nonce: u8,
}
