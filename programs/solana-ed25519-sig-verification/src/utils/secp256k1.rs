use anchor_lang::prelude::*;
use solana_program::instruction::Instruction;
use solana_program::secp256k1_program::ID as SECP256K1_ID;
use crate::error::ErrorCode;

use std::convert::TryInto;

/// Verify Secp256k1Program instruction fields
pub fn verify_secp256k1_ix(ix: &Instruction, eth_address: &[u8], msg: &[u8], sig: &[u8], recovery_id: u8) -> Result<()> {
    if  ix.program_id       != SECP256K1_ID                 ||  // The program id we expect
        ix.accounts.len()   != 0                            ||  // With no context accounts
        ix.data.len()       != (12 + 20 + 64 + 1 + msg.len())   // And data of this size
    {
        return Err(ErrorCode::SigVerificationFailed.into());    // Otherwise, we can already throw err
    }

    check_secp256k1_data(&ix.data, eth_address, msg, sig, recovery_id)?; // If that's not the case, check data

    Ok(())
}

/// Verify serialized Secp256k1Program instruction data
pub fn check_secp256k1_data(data: &[u8], eth_address: &[u8], msg: &[u8], sig: &[u8], recovery_id: u8) -> Result<()> {
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
