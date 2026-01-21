# Solana Ed25519 and Secp256k1 signature verification

On-chain Ed25519 and Secp256k1 signature verification using instruction introspection.

Built for checking Solana and Ethereum signatures, with examples (see tests).

### Why and how

Solana does not have a way to implement [Ed25519](https://ed25519.cr.yp.to/) or [Secp256k1](https://github.com/gavofyork/ethereum/blob/master/secp256k1/secp256k1.c) sig verification on-chain on custom programs. That's why the [native Ed25519Program](https://docs.solana.com/developing/runtime-facilities/programs#ed25519-program) and [native Secp256k1Program](https://docs.solana.com/es/developing/runtime-facilities/programs#secp256k1-program) exist, which have a set of instructions that can, amongst other things, verify signatures for those curves.

Therefore, the way to build custom instructions that "do" sig verification is by actually sending a transaction made of (at least) two instructions, and checking that the native program instruction was sent.

In doing so, these are the possible outcomes:

-   ❌ Native program instruction fails -> Custom instruction is never executed.
-   ❌ Native program instruction not supplied or supplied with wrong values -> Custom instruction fails to check that the Native program instruction was sent with the proper data, therefore gets rejected.
-   ✅ Native program instruction succeeds -> Custom instruction gets executed -> Custom instruction checks that the Native program instruction was sent with the proper data -> If that succeeds, we can say that Custom instruction indirectly verified the signature.

### Instruction introspection

`solana_program` provides us with the [`load_instruction_at_checked`](https://docs.rs/solana-program/latest/solana_program/sysvar/instructions/fn.load_instruction_at_checked.html) function on the `Instructions Sysvar`, that allows us to recover the raw fields of an instruction at a given index (fields are `program_id, accounts, data`).
In order for us to check that that instruction was constructed properly, we need to inspect the data byte array manually.

### Version Information

This project has been upgraded to:
- **Anchor**: 0.32.1
- **Solana CLI**: 3.0.13 (stable)
- **Rust Edition**: 2021

### Building and testing

Install [Anchor](https://project-serum.github.io/anchor/getting-started/installation.html) first.

There are two test files with the same concepts: one, signing using a Solana keypair (Ed25519 signatures); the other one, using an Ethereum Wallet (Secp256k1 signatures).

```bash
yarn install
anchor build
yarn test --skip-build
```

#### Note on Bankrun Tests

⚠️ **Known Issue**: The bankrun tests (in `tests/bankrun/`) currently fail due to a library incompatibility. The `anchor-bankrun` library (version 0.5.0 as of this writing) was designed for Anchor 0.30 and has not yet been updated to support Anchor 0.32.1's internal changes to the IDL format and Program initialization.

The regular Anchor tests (in `tests/anchor/`) **work perfectly** and fully test all signature verification functionality. The bankrun tests are redundant and can be safely skipped until `anchor-bankrun` adds Anchor 0.32+ compatibility.

**Status**:
- ✅ Anchor Tests: 13/13 passing
- ⚠️ Bankrun Tests: Incompatible with Anchor 0.32.1 (library limitation, not code issue)
