//! Risc0 membership-proof guest.
//!
//! Private witness (never leaves the prover's machine):
//! - `secret`: the member's 32-byte root secret
//! - `view_salt`: per-multisig salt (allows commitment rotation without
//!   rotating the root secret)
//! - `path_bits`: leaf index in the Merkle tree
//! - `siblings`: `MERKLE_DEPTH` sibling hashes along the path
//!
//! Public inputs (appear in the journal, on-chain):
//! - `members_root`
//! - `multisig_create_key`
//! - `proposal_id`
//! - `vote_type`
//! - `nullifier`
//!
//! The circuit enforces:
//! 1.  commitment = sha256(DOMAIN || "COMMIT" || secret || view_salt)
//! 2.  merkle_verify(commitment, path_bits, siblings) == members_root
//! 3.  expected_proposal_id = sha256(DOMAIN || "PROPOSAL" || create_key || be(idx))
//!     -- the guest re-derives this from create_key + proposal_index in
//!        the witness and commits only the result, so a malicious prover
//!        cannot lie about scope.
//! 4.  nullifier == sha256(DOMAIN || "NULLIFIER" || secret || pid || ck)
//!     -- note: vote_type is committed in the journal so handlers can
//!        dispatch and a relayer cannot re-route a receipt from
//!        Approve to Reject, but it is NOT in the nullifier preimage.
//!        This is what makes "one vote per member per proposal" hold
//!        across all of propose/approve/reject (see zk_common::VoteType).
//!
//! If any check fails the guest panics and no valid receipt is produced.

#![no_main]

use zk_common::{
    commitment_from_secret, nullifier_from_secret, proposal_id, verify_merkle_path, MerkleRoot,
    ProofJournal, VoteType, MERKLE_DEPTH,
};

risc0_zkvm::guest::entry!(main);

/// Wire-format of what the host feeds into the guest.
/// Using borsh (not bincode) to stay consistent with everything else on-chain.
#[derive(borsh::BorshSerialize, borsh::BorshDeserialize)]
struct GuestInput {
    // --- witness (private) ---
    secret: [u8; 32],
    view_salt: [u8; 32],
    path_bits: u32,
    siblings: [[u8; 32]; MERKLE_DEPTH],

    // --- public inputs ---
    members_root: MerkleRoot,
    multisig_create_key: [u8; 32],
    proposal_index: u64,
    vote_type: VoteType,
}

pub fn main() {
    let input_bytes: Vec<u8> = risc0_zkvm::guest::env::read();
    let input: GuestInput =
        borsh::from_slice(&input_bytes).expect("membership-guest: malformed input");

    // (1) Commitment derivation.
    let commitment = commitment_from_secret(&input.secret, &input.view_salt);

    // (2) Merkle membership proof.
    let ok = verify_merkle_path(
        &commitment,
        input.path_bits,
        &input.siblings,
        &input.members_root,
    );
    assert!(ok, "membership-guest: Merkle path does not match root");

    // (3) Scope derivation.
    let pid = proposal_id(&input.multisig_create_key, input.proposal_index);

    // (4) Nullifier derivation. vote_type is intentionally NOT in the
    //     preimage — see zk_common::VoteType docstring.
    let nullifier =
        nullifier_from_secret(&input.secret, &pid, &input.multisig_create_key);

    // Commit the public journal.
    let journal = ProofJournal {
        members_root: input.members_root,
        multisig_create_key: input.multisig_create_key,
        proposal_id: pid,
        vote_type: input.vote_type,
        nullifier,
    };
    risc0_zkvm::guest::env::commit_slice(&journal.to_bytes());
}
