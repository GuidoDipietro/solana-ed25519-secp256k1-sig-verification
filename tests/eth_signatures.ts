import * as anchor from '@coral-xyz/anchor';
import { Program } from '@coral-xyz/anchor';
import { Signatures } from '../target/types/signatures';
import { ethers } from 'ethers';
import * as assert from 'assert';

// Note: The recovery byte for Secp256k1 signatures has an arbitrary constant of 27 added for these
//       Ethereum and Bitcoin signatures. This is why you will see (recoveryId - 27) throughout the tests.
//       The Solana Secp256k1Program needs the recovery byte to be in the range [0;3].
// Ref:  https://ethereum.github.io/yellowpaper/paper.pdf

describe('Ethereum Signatures', () => {
    const provider = anchor.AnchorProvider.local(undefined, {
        commitment: `confirmed`,
    });
    anchor.setProvider(provider);

    const program = anchor.workspace.Signatures as Program<Signatures>;

    // Solana and Ethereum wallets
    const eth_signer: ethers.Wallet = ethers.Wallet.createRandom();
    const person: anchor.web3.Keypair = anchor.web3.Keypair.generate();

    // Stuff
    const PERSON = { name: 'ben', age: 49 }; // mock data
    let eth_address: string; // Ethereum address to be recovered and checked against
    let full_sig: string; // 64 bytes + recovery byte
    let signature: Uint8Array; // 64 bytes of sig
    let recoveryId: number; // recovery byte (u8)
    let actual_message: Buffer; // actual signed message with Ethereum Message prefix

    /// Sample Create Signature function that signs with ethers signMessage
    async function createSignature(name: string, age: number): Promise<string> {
        // keccak256 hash of the message
        const messageHash: string = ethers.utils.solidityKeccak256(
            ['string', 'uint16'],
            [name, age]
        );

        // get hash as Uint8Array of size 32
        const messageHashBytes: Uint8Array = ethers.utils.arrayify(messageHash);

        // Signed message that is actually this:
        // sign(keccak256("\x19Ethereum Signed Message:\n" + len(messageHash) + messageHash)))
        const signature = await eth_signer.signMessage(messageHashBytes);

        return signature;
    }

    before(async () => {
        // Fund person
        let txid = await provider.connection.requestAirdrop(
            person.publicKey,
            5 * anchor.web3.LAMPORTS_PER_SOL
        );
        let { blockhash, lastValidBlockHeight } =
            await provider.connection.getLatestBlockhash();
        await provider.connection.confirmTransaction({
            signature: txid,
            blockhash,
            lastValidBlockHeight,
        });

        // Signature
        // Full sig consists of 64 bytes + recovery byte
        full_sig = await createSignature(PERSON.name, PERSON.age);

        let full_sig_bytes = ethers.utils.arrayify(full_sig);
        signature = full_sig_bytes.slice(0, 64);
        recoveryId = full_sig_bytes[64] - 27;
        // ^ Why - 27? Check https://ethereum.github.io/yellowpaper/paper.pdf page 27.

        // The message we have to check against is actually this
        // "\x19Ethereum Signed Message:\n" + "32" + keccak256(msg)
        // Since we're hashing with keccak256 the msg len is always 32
        let msg_digest = ethers.utils.arrayify(
            ethers.utils.solidityKeccak256(
                ['string', 'uint16'],
                [PERSON.name, PERSON.age]
            )
        );
        actual_message = Buffer.concat([
            Buffer.from('\x19Ethereum Signed Message:\n32'),
            msg_digest,
        ]);

        // Calculated Ethereum Address (20 bytes) from public key (32 bytes)
        eth_address = ethers.utils
            .computeAddress(eth_signer.publicKey)
            .slice(2);
    });

    it('Verifies correct Ethereum signature', async () => {
        // Construct transaction made of 2 instructions:
        //      - Secp256k1 sig verification instruction to the Secp256k1Program
        //      - Custom instruction to our program
        // The second instruction checks that the 1st one has been sent in the same transaction.
        // It checks that program_id, accounts, and data are what should have been send for
        // the params that we are intending to check.
        // If the first instruction doesn't fail and our instruction manages to deserialize
        // the data and check that it is correct, it means that the sig verification was successful.
        // Otherwise it failed.
        let tx = new anchor.web3.Transaction()
            .add(
                // Secp256k1 instruction
                anchor.web3.Secp256k1Program.createInstructionWithEthAddress({
                    ethAddress: eth_address,
                    message: actual_message,
                    signature: signature,
                    recoveryId: recoveryId,
                })
            )
            .add(
                // Our instruction
                await program.methods
                    .verifySecp(
                        Array.from(ethers.utils.arrayify('0x' + eth_address)),
                        Buffer.from(actual_message),
                        Array.from(signature),
                        recoveryId
                    )
                    .accounts({
                        sender: person.publicKey,
                        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                    })
                    .signers([person])
                    .instruction()
            );

        try {
            const { lastValidBlockHeight, blockhash } =
                await provider.connection.getLatestBlockhash();
            tx.lastValidBlockHeight = lastValidBlockHeight;
            tx.recentBlockhash = blockhash;
            tx.feePayer = person.publicKey;

            tx.sign(person);

            await provider.connection.sendRawTransaction(tx.serialize());

            // If all goes well, we're good!
        } catch (error) {
            assert.fail(
                `Should not have failed with the following error:\n${error.msg}`
            );
        }
    });

    it('Verifies chip signature', async () => {
        const chip_eth_address = '1aaBF638eC3c4A5C2D5cD14fd460Fee2c364c579';
        const chip_actual_message = Buffer.concat([
            Buffer.from('\x19Ethereum Signed Message:\n3'),
            Buffer.from([0x01, 0x02, 0x03]),
        ]);
        const chip_signature = Uint8Array.from(
            Buffer.from(
                '93137bc7bfeaa86e26c6a9bbd6fb8acdf73ed5fd232cc2be1a0714f583f04d2e' +
                    '7f5d7c2461daf8649587c3c510fce05a74146cbe79341427065d0d878d154a1b',
                'hex'
            )
        );
        const chip_recoveryId = 27 - 27;

        let tx = new anchor.web3.Transaction()
            .add(
                // Secp256k1 instruction
                anchor.web3.Secp256k1Program.createInstructionWithEthAddress({
                    ethAddress: chip_eth_address,
                    message: chip_actual_message,
                    signature: chip_signature,
                    recoveryId: chip_recoveryId,
                })
            )
            .add(
                // Our instruction
                await program.methods
                    .verifySecp(
                        Array.from(
                            ethers.utils.arrayify('0x' + chip_eth_address)
                        ),
                        Buffer.from(chip_actual_message),
                        Array.from(chip_signature),
                        chip_recoveryId
                    )
                    .accounts({
                        sender: person.publicKey,
                        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                    })
                    .signers([person])
                    .instruction()
            );

        try {
            const { lastValidBlockHeight, blockhash } =
                await provider.connection.getLatestBlockhash();
            tx.lastValidBlockHeight = lastValidBlockHeight;
            tx.recentBlockhash = blockhash;
            tx.feePayer = person.publicKey;

            tx.sign(person);

            await provider.connection.sendRawTransaction(tx.serialize());

            // If all goes well, we're good!
        } catch (error) {
            assert.fail(
                `Should not have failed with the following error:\n${error.msg}`
            );
        }
    });

    it('Fails to verify wrong signature', async () => {
        // Construct transaction made of 2 instructions:
        //      - Secp256k1 sig verification instruction to the Secp256k1Program
        //      - Custom instruction to our program
        // The second instruction checks that the 1st one has been sent in the same transaction.
        // It checks that program_id, accounts, and data are what should have been send for
        // the params that we are intending to check.
        // If the first instruction doesn't fail and our instruction manages to deserialize
        // the data and check that it is correct, it means that the sig verification was successful.
        // Otherwise it failed.
        let tx = new anchor.web3.Transaction()
            .add(
                // Secp256k1 instruction
                anchor.web3.Secp256k1Program.createInstructionWithEthAddress({
                    ethAddress: eth_address,
                    message: Buffer.from('bad message'), // will fail to verify
                    signature: signature,
                    recoveryId: recoveryId,
                })
            )
            .add(
                // Our instruction
                await program.methods
                    .verifySecp(
                        Array.from(ethers.utils.arrayify('0x' + eth_address)),
                        Buffer.from(actual_message),
                        Array.from(signature),
                        recoveryId
                    )
                    .accounts({
                        sender: person.publicKey,
                        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                    })
                    .signers([person])
                    .instruction()
            );

        // Send tx
        try {
            const { lastValidBlockHeight, blockhash } =
                await provider.connection.getLatestBlockhash();
            tx.lastValidBlockHeight = lastValidBlockHeight;
            tx.recentBlockhash = blockhash;
            tx.feePayer = person.publicKey;

            tx.sign(person);

            await provider.connection.sendRawTransaction(tx.serialize());

            assert.fail(
                'Should have failed to verify an invalid Secp256k1 signature.'
            );
        } catch (error) {
            assert.equal(
                error.transactionMessage,
                'Transaction precompile verification failure InvalidAccountIndex'
            );
        }
    });

    it('Fails to execute custom instruction if Secp256k1Program sig verification is missing', async () => {
        // Everything is correct, but since we did not attach the Secp256k1Program
        // instruction, our custom instruction will fail to execute.
        let tx = new anchor.web3.Transaction().add(
            // Our instruction
            await program.methods
                .verifySecp(
                    Array.from(ethers.utils.arrayify('0x' + eth_address)),
                    Buffer.from(actual_message),
                    Array.from(signature),
                    recoveryId
                )
                .accounts({
                    sender: person.publicKey,
                    ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                })
                .signers([person])
                .instruction()
        );

        // Send tx
        try {
            const { lastValidBlockHeight, blockhash } =
                await provider.connection.getLatestBlockhash();
            tx.lastValidBlockHeight = lastValidBlockHeight;
            tx.recentBlockhash = blockhash;
            tx.feePayer = person.publicKey;

            tx.sign(person);

            await provider.connection.sendRawTransaction(tx.serialize());

            assert.fail(
                'Should have failed to execute custom instruction with missing Ed25519Program instruction.'
            );
        } catch (error) {
            assert.ok(
                error.logs
                    .join('')
                    .includes(
                        'Program log: AnchorError occurred. Error Code: SigVerificationFailed'
                    )
            );
        }
    });

    it('Fails to execute custom instruction if Ed25519Program ix corresponds to another signature', async () => {
        // Let's send a Secp256k1Program instruction that gets verified,
        // but that does not correspond to the message we need to verify

        // See before() for details
        const SOMEONE = { name: 'anatoly', age: 48 };

        let other_full_sig = await createSignature(SOMEONE.name, SOMEONE.age);
        let other_full_sig_bytes = ethers.utils.arrayify(other_full_sig);
        let other_signature = other_full_sig_bytes.slice(0, 64);
        let other_recoveryId = other_full_sig_bytes[64] - 27;
        let other_msg_digest = ethers.utils.arrayify(
            ethers.utils.solidityKeccak256(
                ['string', 'uint16'],
                [SOMEONE.name, SOMEONE.age]
            )
        );
        let other_actual_message = Buffer.concat([
            Buffer.from('\x19Ethereum Signed Message:\n32'),
            other_msg_digest,
        ]);

        // Transaction with two instructions:
        //      - Secp256k1Program instruction with successful signature verification
        //      - Custom instruction with different params
        // The transaction will get rejected because transaction introspection will
        // find that the Secp256k1Program instruction that we submitted does not match
        // the arguments of our custom transaction.
        let tx = new anchor.web3.Transaction()
            .add(
                // Secp256k1 instruction (suceeds)
                anchor.web3.Secp256k1Program.createInstructionWithEthAddress({
                    ethAddress: eth_address,
                    message: other_actual_message,
                    signature: other_signature,
                    recoveryId: other_recoveryId,
                })
            )
            .add(
                // Our instruction (fails due to introspection checks)
                await program.methods
                    .verifySecp(
                        Array.from(ethers.utils.arrayify('0x' + eth_address)),
                        Buffer.from(actual_message),
                        Array.from(signature),
                        recoveryId
                    )
                    .accounts({
                        sender: person.publicKey,
                        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                    })
                    .signers([person])
                    .instruction()
            );

        // Send tx
        try {
            const { lastValidBlockHeight, blockhash } =
                await provider.connection.getLatestBlockhash();
            tx.lastValidBlockHeight = lastValidBlockHeight;
            tx.recentBlockhash = blockhash;
            tx.feePayer = person.publicKey;

            tx.sign(person);

            await provider.connection.sendRawTransaction(tx.serialize());

            assert.fail('Should have failed after introspection checks.');
        } catch (error) {
            assert.ok(
                error.logs
                    .join('')
                    .includes(
                        'Program log: AnchorError occurred. Error Code: SigVerificationFailed'
                    )
            );
        }
    });
});
