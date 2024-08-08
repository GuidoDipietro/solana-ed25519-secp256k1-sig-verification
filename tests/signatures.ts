import * as anchor from '@coral-xyz/anchor';
import { Program } from '@coral-xyz/anchor';
import { Signatures } from '../target/types/signatures';
import * as ed from '@noble/ed25519';
import * as assert from 'assert';

describe('Solana signatures', () => {
    const provider = anchor.AnchorProvider.env();
    anchor.setProvider(provider);

    const program = anchor.workspace.Signatures as Program<Signatures>;

    // Stuff
    const MSG = Uint8Array.from(
        Buffer.from('this is such a good message to sign')
    );
    let person: anchor.web3.Keypair;
    let signature: Uint8Array;

    before(async () => {
        // Create and fund person
        person = anchor.web3.Keypair.generate();

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

        // Calculate Ed25519 signature
        signature = await ed.sign(MSG, person.secretKey.slice(0, 32));
    });

    it('Verifies correct signature', async () => {
        // Construct transaction made of 2 instructions:
        //      - Ed25519 sig verification instruction to the Ed25519Program
        //      - Custom instruction to our program
        // The second instruction checks that the 1st one has been sent in the same transaction.
        // It checks that program_id, accounts, and data are what should have been send for
        // the params that we are intending to check.
        // If the first instruction doesn't fail and our instruction manages to deserialize
        // the data and check that it is correct, it means that the sig verification was successful.
        // Otherwise it failed.
        let tx = new anchor.web3.Transaction()
            .add(
                // Ed25519 instruction
                anchor.web3.Ed25519Program.createInstructionWithPublicKey({
                    publicKey: person.publicKey.toBytes(),
                    message: MSG,
                    signature: signature,
                })
            )
            .add(
                // Our instruction
                await program.methods
                    .verifyEd25519(
                        Array.from(person.publicKey.toBuffer()),
                        Buffer.from(MSG),
                        Array.from(signature)
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

            // If all goes well, we're good!
        } catch (error) {
            assert.fail(
                `Should not have failed with the following error:\n${error.msg}`
            );
        }
    });

    it('Fails to verify wrong signature', async () => {
        // Wrong message in order for sig verification to fail
        const WRONG_MSG = Uint8Array.from(Buffer.from('wrong message'));

        // Construct transaction made of 2 instructions:
        //      - Ed25519 sig verification instruction to the Ed25519Program
        //      - Custom instruction to our program
        // The second instruction checks that the 1st one has been sent in the same transaction.
        // It checks that program_id, accounts, and data are what should have been send for
        // the params that we are intending to check.
        // If the first instruction doesn't fail and our instruction manages to deserialize
        // the data and check that it is correct, it means that the sig verification was successful.
        // Otherwise it failed.
        let tx = new anchor.web3.Transaction()
            .add(
                // Ed25519 instruction
                anchor.web3.Ed25519Program.createInstructionWithPublicKey({
                    publicKey: person.publicKey.toBytes(),
                    message: WRONG_MSG, // will fail to verify!
                    signature: signature,
                })
            )
            .add(
                // Our instruction
                await program.methods
                    .verifyEd25519(
                        Array.from(person.publicKey.toBuffer()),
                        Buffer.from(MSG),
                        Array.from(signature)
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
                'Should have failed to verify an invalid Ed25519 signature.'
            );
        } catch (error) {
            assert.equal(
                error.transactionMessage,
                'Transaction precompile verification failure InvalidAccountIndex'
            );
        }
    });

    it('Fails to execute custom instruction if Ed25519Program sig verification is missing', async () => {
        // Everything is correct, but since we did not attach the Ed25519Program
        // instruction, our custom instruction will fail to execute.
        let tx = new anchor.web3.Transaction().add(
            // Our instruction
            await program.methods
                .verifyEd25519(
                    Array.from(person.publicKey.toBuffer()),
                    Buffer.from(MSG),
                    Array.from(signature)
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
        // Let's send an Ed25519Program instruction that gets verified,
        // but that does not correspond to the message we need to verify

        const OTHER_MSG = Uint8Array.from(
            Buffer.from('this is another pretty message')
        );
        let other_signature: Uint8Array = await ed.sign(
            OTHER_MSG,
            person.secretKey.slice(0, 32)
        );

        // Transaction with two instructions:
        //      - Ed25519Program instruction with successful signature verification
        //      - Custom instruction with different params
        // The transaction will get rejected because transaction introspection will
        // find that the Ed25519Program instruction that we submitted does not match
        // the arguments of our custom transaction.
        let tx = new anchor.web3.Transaction()
            .add(
                // Ed25519 instruction (suceeds)
                anchor.web3.Ed25519Program.createInstructionWithPublicKey({
                    publicKey: person.publicKey.toBytes(),
                    message: OTHER_MSG,
                    signature: other_signature,
                })
            )
            .add(
                // Our instruction (fails due to introspection checks)
                await program.methods
                    .verifyEd25519(
                        Array.from(person.publicKey.toBuffer()),
                        Buffer.from(MSG),
                        Array.from(signature)
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
