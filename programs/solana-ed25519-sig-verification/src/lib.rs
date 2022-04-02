//! Very reduced Solana program that indirectly validates
//! Ed25519 signatures by using instruction introspection
//!
//! Single-file, made for learning / teaching / example purposes.
//!

use anchor_lang::prelude::*;
use solana_program::instruction::Instruction;
use solana_program::sysvar::instructions::{ID as IX_ID, load_instruction_at_checked};

use solana_program::ed25519_program::{ID as ED25519_ID};
use solana_program::secp256k1_program::{ID as SECP256K1_ID};

use std::convert::TryInto;

declare_id!("DHxesXA69rUmz5AJ1CnLCQezUzQR5j7KKTwTp1zZPc9j");

/// Main module
#[program]
pub mod signatures {
    use super::*;

    /// External instruction that only gets executed if
    /// an `Ed25519Program.createInstructionWithPublicKey`
    /// instruction was sent in the same transaction.
    pub fn verify_ed25519(ctx: Context<Verify>, pubkey: [u8; 32], msg: Vec<u8>, sig: [u8; 64]) -> ProgramResult {
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
    pub fn verify_secp(ctx: Context<Verify>, eth_address: [u8; 20], msg: Vec<u8>, sig: [u8; 64], recovery_id: u8) -> ProgramResult {
        // Get what should be the Secp256k1Program instruction
        let ix: Instruction = load_instruction_at_checked(0, &ctx.accounts.ix_sysvar)?;

        // Check that ix is what we expect to have been sent
        utils::verify_secp256k1_ix(&ix, &eth_address, &msg, &sig, recovery_id)?;

        // Do other stuff
        
        Ok(())
    }
}

/// This mod contains functions that validate that an instruction
/// is constructed the way we expect. In this case, this is for
/// `Ed25519Program.createInstructionWithPublicKey()` and
/// `Secp256k1Program.createInstructionWithEthAddress()` instructions.
pub mod utils {
    use super::*;

    /// Verify Ed25519Program instruction fields
    pub fn verify_ed25519_ix(ix: &Instruction, pubkey: &[u8], msg: &[u8], sig: &[u8]) -> ProgramResult {
        if  ix.program_id       != ED25519_ID                   ||  // The program id we expect
            ix.accounts.len()   != 0                            ||  // With no context accounts
            ix.data.len()       != (16 + 64 + 32 + msg.len())       // And data of this size
        {
            return Err(ErrorCode::SigVerificationFailed.into());    // Otherwise, we can already throw err
        }

        check_ed25519_data(&ix.data, pubkey, msg, sig)?;            // If that's not the case, check data

        Ok(())
    }

    /// Verify Secp256k1 instruction fields
    pub fn verify_secp256k1_ix(ix: &Instruction, eth_address: &[u8], msg: &[u8], sig: &[u8], recovery_id: u8) -> ProgramResult {
        if  ix.program_id       != SECP256K1_ID                 ||  // The program id we expect
            ix.accounts.len()   != 0                            ||  // With no context accounts
            ix.data.len()       != (12 + 20 + 64 + 1 + msg.len())   // And data of this size
        {
            return Err(ErrorCode::SigVerificationFailed.into());    // Otherwise, we can already throw err
        }

        check_secp256k1_data(&ix.data, eth_address, msg, sig, recovery_id)?; // If that's not the case, check data

        Ok(())
    }

    /// Verify serialized Ed25519Program instruction data
    pub fn check_ed25519_data(data: &[u8], pubkey: &[u8], msg: &[u8], sig: &[u8]) -> ProgramResult {
        // According to this layout used by the Ed25519Program
        // https://github.com/solana-labs/solana-web3.js/blob/master/src/ed25519-program.ts#L33

        // "Deserializing" byte slices

        let num_signatures                  = &[data[0]];        // Byte  0
        let padding                         = &[data[1]];        // Byte  1
        let signature_offset                = &data[2..=3];      // Bytes 2,3
        let signature_instruction_index     = &data[4..=5];      // Bytes 4,5
        let public_key_offset               = &data[6..=7];      // Bytes 6,7
        let public_key_instruction_index    = &data[8..=9];      // Bytes 8,9
        let message_data_offset             = &data[10..=11];    // Bytes 10,11
        let message_data_size               = &data[12..=13];    // Bytes 12,13
        let message_instruction_index       = &data[14..=15];    // Bytes 14,15

        let data_pubkey                     = &data[16..16+32];  // Bytes 16..16+32
        let data_sig                        = &data[48..48+64];  // Bytes 48..48+64
        let data_msg                        = &data[112..];      // Bytes 112..end

        // Expected values

        let exp_public_key_offset:      u16 = 16; // 2*u8 + 7*u16
        let exp_signature_offset:       u16 = exp_public_key_offset + pubkey.len() as u16;
        let exp_message_data_offset:    u16 = exp_signature_offset + sig.len() as u16;
        let exp_num_signatures:          u8 = 1;
        let exp_message_data_size:      u16 = msg.len().try_into().unwrap();

        // Header and Arg Checks

        // Header
        if  num_signatures                  != &exp_num_signatures.to_le_bytes()        ||
            padding                         != &[0]                                     ||
            signature_offset                != &exp_signature_offset.to_le_bytes()      ||
            signature_instruction_index     != &u16::MAX.to_le_bytes()                  ||
            public_key_offset               != &exp_public_key_offset.to_le_bytes()     ||
            public_key_instruction_index    != &u16::MAX.to_le_bytes()                  ||
            message_data_offset             != &exp_message_data_offset.to_le_bytes()   ||
            message_data_size               != &exp_message_data_size.to_le_bytes()     ||
            message_instruction_index       != &u16::MAX.to_le_bytes()  
        {
            return Err(ErrorCode::SigVerificationFailed.into());
        }

        // Arguments
        if  data_pubkey != pubkey   ||
            data_msg    != msg      ||
            data_sig    != sig
        {
            return Err(ErrorCode::SigVerificationFailed.into());
        }

        Ok(())
    }

    /// Verify serialized Secp256k1Program instruction data
    pub fn check_secp256k1_data(data: &[u8], eth_address: &[u8], msg: &[u8], sig: &[u8], recovery_id: u8) -> ProgramResult {
        // According to this layout used by the Secp256k1Program
        // https://github.com/solana-labs/solana-web3.js/blob/master/src/secp256k1-program.ts#L49

        // "Deserializing" byte slices

        let num_signatures                  = &[data[0]];           // Byte  0
        let signature_offset                = &data[1..=2];         // Bytes 1,2
        let signature_instruction_index     = &[data[3]];           // Byte  3
        let eth_address_offset              = &data[4..=5];         // Bytes 4,5
        let eth_address_instruction_index   = &[data[6]];           // Byte  6
        let message_data_offset             = &data[7..=8];         // Bytes 7,8
        let message_data_size               = &data[9..=10];        // Bytes 9,10
        let message_instruction_index       = &[data[11]];          // Byte  11

        let data_eth_address                = &data[12..12+20];     // Bytes 12..12+20
        let data_sig                        = &data[32..32+64];     // Bytes 32..32+64
        let data_recovery_id                = &[data[96]];          // Byte  96
        let data_msg                        = &data[97..];          // Bytes 97..end

        // Expected values

        const SIGNATURE_OFFSETS_SERIALIZED_SIZE:    u16 = 11;
        const DATA_START:                           u16 = 1 + SIGNATURE_OFFSETS_SERIALIZED_SIZE;

        let msg_len:                    u16 = msg.len().try_into().unwrap();
        let eth_address_len:            u16 = eth_address.len().try_into().unwrap();
        let sig_len:                    u16 = sig.len().try_into().unwrap();

        let exp_eth_address_offset:     u16 = DATA_START;
        let exp_signature_offset:       u16 = DATA_START + eth_address_len;
        let exp_message_data_offset:    u16 = exp_signature_offset + sig_len + 1;
        let exp_num_signatures:          u8 = 1;

        // Header and Arg Checks

        // Header
        if  num_signatures                  != &exp_num_signatures.to_le_bytes()         ||
            signature_offset                != &exp_signature_offset.to_le_bytes()       ||
            signature_instruction_index     != &[0]                                      ||
            eth_address_offset              != &exp_eth_address_offset.to_le_bytes()     ||
            eth_address_instruction_index   != &[0]                                      ||
            message_data_offset             != &exp_message_data_offset.to_le_bytes()    ||
            message_data_size               != &msg_len.to_le_bytes()                    ||
            message_instruction_index       != &[0]
        {
            return Err(ErrorCode::SigVerificationFailed.into());
        }

        // Arguments
        if  data_eth_address    != eth_address      ||
            data_sig            != sig              ||
            data_recovery_id    != &[recovery_id]   ||
            data_msg            != msg
        {
            return Err(ErrorCode::SigVerificationFailed.into());
        }

        Ok(())
    }
}

/// Context accounts
#[derive(Accounts)]
pub struct Verify<'info> {
    pub sender: Signer<'info>,

    /// The address check is needed because otherwise
    /// the supplied Sysvar could be anything else.
    /// The Instruction Sysvar has not been implemented
    /// in the Anchor framework yet, so this is the safe approach.
    #[account(address = IX_ID)]
    pub ix_sysvar: AccountInfo<'info>,
}

/// Custom error codes
#[error]
pub enum ErrorCode {
    #[msg("Signature verification failed.")]
    SigVerificationFailed,
}
