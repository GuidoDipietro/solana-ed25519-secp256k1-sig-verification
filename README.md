# Solana Ed25519 signature verification

On-chain Ed25519 signature verification using instruction introspection.

### Why and how

Solana does not have a way to implement [Ed25519](https://ed25519.cr.yp.to/) sig verification on-chain on custom programs. That's why the [native Ed25519Program](https://docs.solana.com/developing/runtime-facilities/programs#ed25519-program) exists, which has a set of instructions that can, amongst other things, verify Ed25519 signatures.

Therefore, the way to build custom instructions that "do" Ed25519 sig verification is by actually sending a transaction made of (at least) two instructions, and checking that the Ed25519 instruction was sent.

In doing so, these are the possible outcomes:

- ❌ Ed25519 instruction fails -> Custom instruction is never executed.
- ❌ Ed25519 instruction not supplied or supplied with wrong values -> Custom instruction fails to check that the Ed25519 instruction was sent with the proper data, therefore gets rejected.
- ✅ Ed25519 instruction succeeds -> Custom instruction gets executed -> Custom instruction checks that the Ed25519 instruction was sent with the proper data -> If that succeeds, we can say that Custom instruction indirectly verified the Ed25519 signature.


### Instruction introspection

`solana_program` provides us with the [`load_instruction_at_checked`](https://docs.rs/solana-program/latest/solana_program/sysvar/instructions/fn.load_instruction_at_checked.html) function, that allows us to recover the raw fields of an instruction at a given index (`program_id, accounts, data`).  
In order for us to check that that instruction was constructed properly, we need to inspect the data byte array manually.

### Building and testing

Install [Anchor](https://project-serum.github.io/anchor/getting-started/installation.html) first.

```bash
yarn install
anchor test
```
