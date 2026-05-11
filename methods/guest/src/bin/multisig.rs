#![no_main]

// Outer LEZ guest for the private multisig. The `#[lez_program]` macro on
// `multisig_program::lib` generates the `main` symbol that decodes the
// instruction, dispatches to the handler, and commits the post-state
// journal. Inside any handler that consumes a membership proof, the
// assumption injected by the prover is consumed by
// `risc0_zkvm::guest::env::verify(MEMBERSHIP_PROOF_ID, journal_bytes)`.
risc0_zkvm::guest::entry!(multisig_program::main);
