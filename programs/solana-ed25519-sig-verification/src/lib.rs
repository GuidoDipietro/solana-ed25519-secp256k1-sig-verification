//! Very reduced Solana program that indirectly validates
//! Ed25519/Secp256k1 signatures by using instruction introspection
//!
//! Made for learning / teaching / example purposes.
//!

use anchor_lang::prelude::*;
use anchor_lang::solana_program::instruction::Instruction;
use anchor_lang::solana_program::sysvar::instructions::{load_instruction_at_checked, ID as IX_ID};

pub mod error;
pub mod utils;

declare_id!("DHxesXA69rUmz5AJ1CnLCQezUzQR5j7KKTwTp1zZPc9j");

/// Main module
#[program]
pub mod signatures {
    use super::*;

    /// External instruction that only gets executed if
    /// an `Ed25519Program.createInstructionWithPublicKey`
    /// instruction was sent in the same transaction.
    pub fn verify_ed25519(
        ctx: Context<Verify>,
        pubkey: [u8; 32],
        msg: Vec<u8>,
        sig: [u8; 64],
    ) -> Result<()> {
        // Get what should be the Ed25519Program instruction
        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        // Check that ix is what we expect to have been sent
        utils::verify_ed25519_ix(&ix, &pubkey, &msg, &sig)?;

        // Do other stuff

        Ok(())
    }

    /// External instruction that only gets executed if
    /// a `Secp256k1Program.createInstructionWithEthAddress`
    /// instruction was sent in the same transaction.
    pub fn verify_secp(
        ctx: Context<Verify>,
        eth_address: [u8; 20],
        msg: Vec<u8>,
        sig: [u8; 64],
        recovery_id: u8,
    ) -> Result<()> {
        // Get what should be the Secp256k1Program instruction
        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        // Check that ix is what we expect to have been sent
        utils::verify_secp256k1_ix(&ix, &eth_address, &msg, &sig, recovery_id)?;

        // Do other stuff

        Ok(())
    }
}

/// Context accounts
#[derive(Accounts)]
pub struct Verify<'info> {
    pub sender: Signer<'info>,

    /// CHECK: The address check is needed because otherwise
    /// the supplied Sysvar could be anything else.
    /// The Instruction Sysvar has not been implemented
    /// in the Anchor framework yet, so this is the safe approach.
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>,
}
