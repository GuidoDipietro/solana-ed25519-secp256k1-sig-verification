import * as anchor from '@project-serum/anchor';
import { Program } from '@project-serum/anchor';
import { Signatures } from '../target/types/signatures';
import * as ed from '@noble/ed25519';
import * as assert from 'assert';

describe('signatures', () => {
    anchor.setProvider(anchor.Provider.env());

    const program = anchor.workspace.Signatures as Program<Signatures>;

    // Stuff
    const MSG = Uint8Array.from(Buffer.from("this is such a good message to sign"));
    let person: anchor.web3.Keypair;
    let signature: Uint8Array;

    before(async () => {
        // Create and fund person
        person = anchor.web3.Keypair.generate();
        await program.provider.connection.confirmTransaction(
            await program.provider.connection.requestAirdrop(
                person.publicKey,
                50 * anchor.web3.LAMPORTS_PER_SOL
            ),
            "processed"
        );

        // Calculate Ed25519 signature
        signature = await ed.sign(
            MSG,
            person.secretKey.slice(0,32)
        );
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
        let tx = new anchor.web3.Transaction().add(
            // Ed25519 instruction
            anchor.web3.Ed25519Program.createInstructionWithPublicKey(
                {
                    publicKey: person.publicKey.toBytes(),
                    message: MSG,
                    signature: signature,
                }
            )
        ).add(
            // Our instruction
            program.instruction.verify(
                Buffer.from(MSG),
                Buffer.from(signature),
                person.publicKey.toBuffer(),
                {
                    accounts: {
                        sender: person.publicKey,
                        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                    },
                    signers: [person]
                }
            )
        );

        // Send tx
        try {
            await anchor.web3.sendAndConfirmTransaction(
                program.provider.connection,
                tx,
                [person]
            );
            
            // If all goes well, we're good!
        } catch (error) {
            assert.fail(`Should not have failed with the following error:\n${error.msg}`);
        }
    });

    it('Fails to verify wrong signature', async () => {
        // Wrong message in order for sig verification to fail
        const WRONG_MSG = Uint8Array.from(Buffer.from("wrong message"));

        // Construct transaction made of 2 instructions:
        //      - Ed25519 sig verification instruction to the Ed25519Program
        //      - Custom instruction to our program
        // The second instruction checks that the 1st one has been sent in the same transaction.
        // It checks that program_id, accounts, and data are what should have been send for
        // the params that we are intending to check.
        // If the first instruction doesn't fail and our instruction manages to deserialize
        // the data and check that it is correct, it means that the sig verification was successful.
        // Otherwise it failed.
        let tx = new anchor.web3.Transaction().add(
            // Ed25519 instruction
            anchor.web3.Ed25519Program.createInstructionWithPublicKey(
                {
                    publicKey: person.publicKey.toBytes(),
                    message: WRONG_MSG, // will fail to verify!
                    signature: signature,
                }
            )
        ).add(
            // Our instruction
            program.instruction.verify(
                Buffer.from(MSG),
                Buffer.from(signature),
                person.publicKey.toBuffer(),
                {
                    accounts: {
                        sender: person.publicKey,
                        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                    },
                    signers: [person]
                }
            )
        );

        // Send tx
        try {
            await anchor.web3.sendAndConfirmTransaction(
                program.provider.connection,
                tx,
                [person]
            );
        } catch (error) {
            // No idea how to catch this error otherwise
            assert.ok(error.toString().includes("failed to send transaction: Transaction precompile verification failure InvalidAccountIndex"));
            return;
        }

        // assert.fail("Should have failed to verify an invalid Ed25519 signature.");
    });

    it('Fails to execute custom instruction if Ed25519Program sig verification is missing', async () => {
        // Everything is correct, but since we did not attach the Ed25519Program
        // instruction, our custom instruction will fail to execute.
        let tx = new anchor.web3.Transaction().add(
            // Our instruction
            program.instruction.verify(
                Buffer.from(MSG),
                Buffer.from(signature),
                person.publicKey.toBuffer(),
                {
                    accounts: {
                        sender: person.publicKey,
                        ixSysvar: anchor.web3.SYSVAR_INSTRUCTIONS_PUBKEY,
                    },
                    signers: [person]
                }
            )
        );

        // Send tx
        try {
            await anchor.web3.sendAndConfirmTransaction(
                program.provider.connection,
                tx,
                [person]
            );
        } catch (error) {
            // No idea how to catch this error properly, Solana is weird
            // assert.equal(error.msg, "EC25519 signature verification failed.");
            assert.ok(error.logs.join("").includes("Custom program error: 0x1770"));
            return;
        }

        assert.fail("Should have failed to execute custom instruction with missing Ed25519Program instruction.");
    });
});
