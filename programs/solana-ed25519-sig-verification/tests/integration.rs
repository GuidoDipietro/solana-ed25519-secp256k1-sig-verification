use anchor_lang::prelude::AccountMeta;
use bytemuck::bytes_of;
use solana_program::instruction::Instruction;
use solana_program_test::{processor, tokio, ProgramTest};
use solana_sdk::{
  account::AccountSharedData, pubkey::Pubkey, signature::Keypair, signer::Signer,
  transaction::Transaction,
};
use anchor_lang::InstructionData;

#[tokio::test]
async fn test_program() {
    let mut validator: ProgramTest = ProgramTest::default();
    validator.add_program("signatures", signatures::ID, processor!(signatures::entry));

    let person = add_account(&mut validator);
    let other_person = add_account(&mut validator);

    let mut context = validator.start_with_context().await;

    // ---

    let message = "this is such a good message to sign".as_bytes();
    let signature = other_person.sign_message(message);

    // ---

    let sig_ix = ed25519_create_ix_with_pubkey(
        person.pubkey(),
        message,
        &signature.as_ref(), // shouldn't verify
    );

    let custom_ix = Instruction::new_with_bytes(
        signatures::ID,
        &signatures::instruction::VerifyEd25519 {
            pubkey: person.pubkey().to_bytes(),
            msg: message.to_vec(),
            sig: signature.into(),
        }.data(),
        vec![
            AccountMeta::new(person.pubkey(), true),
            AccountMeta::new(solana_program::sysvar::instructions::ID, false),
        ],
    );

    let tx = Transaction::new_signed_with_payer(
        &[sig_ix, custom_ix],
        Some(&person.pubkey()),
        &vec![&person],
        context.banks_client.get_latest_blockhash().await.unwrap(),
    );

    let res = context.banks_client.process_transaction_with_metadata(tx).await;

    println!("{:?}", res.unwrap().metadata.unwrap().log_messages);
}

fn add_account(validator: &mut ProgramTest) -> Keypair {
    let keypair = Keypair::new();
    let account = AccountSharedData::new(1_000_000_000, 0, &solana_sdk::system_program::id());
    validator.add_account(keypair.pubkey(), account.into());
    keypair
}

fn ed25519_create_ix_with_pubkey(pubkey: Pubkey, message: &[u8], signature: &[u8]) -> Instruction {
    use solana_sdk::ed25519_instruction::*;

    let pubkey = pubkey.to_bytes();

    assert_eq!(pubkey.len(), PUBKEY_SERIALIZED_SIZE);
    assert_eq!(signature.len(), SIGNATURE_SERIALIZED_SIZE);

    let mut instruction_data = Vec::with_capacity(
        DATA_START
            .saturating_add(SIGNATURE_SERIALIZED_SIZE)
            .saturating_add(PUBKEY_SERIALIZED_SIZE)
            .saturating_add(message.len()),
    );

    let num_signatures: u8 = 1;
    let public_key_offset = DATA_START;
    let signature_offset = public_key_offset.saturating_add(PUBKEY_SERIALIZED_SIZE);
    let message_data_offset = signature_offset.saturating_add(SIGNATURE_SERIALIZED_SIZE);

    // add padding byte so that offset structure is aligned
    instruction_data.extend_from_slice(bytes_of(&[num_signatures, 0]));

    // to make this compile just edit your local definition of Ed25519SignatureOffsets to have pub fields
    let offsets = Ed25519SignatureOffsets {
        signature_offset: signature_offset as u16,
        signature_instruction_index: u16::MAX,
        public_key_offset: public_key_offset as u16,
        public_key_instruction_index: u16::MAX,
        message_data_offset: message_data_offset as u16,
        message_data_size: message.len() as u16,
        message_instruction_index: u16::MAX,
    };

    instruction_data.extend_from_slice(bytes_of(&offsets));

    debug_assert_eq!(instruction_data.len(), public_key_offset);

    instruction_data.extend_from_slice(&pubkey);

    debug_assert_eq!(instruction_data.len(), signature_offset);

    instruction_data.extend_from_slice(&signature);

    debug_assert_eq!(instruction_data.len(), message_data_offset);

    instruction_data.extend_from_slice(message);

    Instruction {
        program_id: solana_sdk::ed25519_program::id(),
        accounts: vec![],
        data: instruction_data,
    }
}
