//! Shared types for the private multisig ZK layer.
//!
//! These types are used in three places:
//! 1. The Risc0 membership-proof guest (inside `membership_circuit/guest`)
//! 2. The host-side prover (inside `membership_circuit`)
//! 3. The LEZ multisig program (inside `multisig_program`) when verifying receipts
//!
//! Everything here is `no_std`-friendly so the same crate can be pulled into
//! the guest build.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

use alloc::vec::Vec;
use borsh::{BorshDeserialize, BorshSerialize};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Merkle tree depth. 2^10 = 1024 members max per multisig.
/// Grow if needed; every +1 adds one sibling to the witness (32 bytes) and
/// one compression to prove (negligible on Risc0's SHA accelerator).
pub const MERKLE_DEPTH: usize = 10;

/// Versioned domain tag. Change on breaking circuit changes.
pub const DOMAIN_TAG: &[u8] = b"lez-private-multisig-v1";

/// A 32-byte commitment — sha256(secret || view_salt).
pub type Commitment = [u8; 32];

/// A 32-byte nullifier — scoped to (proposal, vote kind, multisig).
pub type Nullifier = [u8; 32];

/// Merkle root over member commitments. Leaves are commitments;
/// empty slots use `EMPTY_LEAF`.
pub type MerkleRoot = [u8; 32];

/// Value used for unfilled leaves. Choosing a fixed non-zero bytestring
/// prevents `commitment == 0` from accidentally matching an empty slot.
pub const EMPTY_LEAF: [u8; 32] = *b"lez-private-multisig-empty-leaf!";

/// Kind of vote being cast. Committed in the journal so handlers can
/// dispatch and a relayer cannot re-route a receipt from approve to
/// reject — but NOT in the nullifier preimage.
///
/// Rationale: the nullifier is the per-(member, proposal) double-vote tag.
/// If `vote_type` were in its preimage, the same member could mint
/// distinct nullifiers for Approve and Reject and have both votes
/// counted. Scoping the nullifier only to `(secret, proposal, multisig)`,
/// combined with `nullifier_used` checking both buckets, gives
/// single-vote-per-member semantics across propose/approve/reject.
/// Propose mints an `Approve`-type receipt — it counts as the proposer's
/// one approval, and a subsequent `Approve` from the same member
/// collides correctly.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, Hash, BorshSerialize, BorshDeserialize, Serialize, Deserialize,
)]
#[borsh(use_discriminant = true)]
#[repr(u8)]
pub enum VoteType {
    Approve = 2,
    Reject = 3,
}

impl VoteType {
    pub fn as_byte(self) -> u8 {
        self as u8
    }
}

/// Public journal committed by the membership-proof guest.
///
/// Everything in here becomes on-chain data visible to the multisig program
/// and to external observers. The member's secret and Merkle path are NOT here
/// (those are the private witness).
#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize, Serialize, Deserialize)]
pub struct ProofJournal {
    /// Merkle root of the member set at the time of proving.
    pub members_root: MerkleRoot,
    /// Which multisig this proof is scoped to.
    pub multisig_create_key: [u8; 32],
    /// The proposal being voted on (derived from create_key + proposal_index).
    pub proposal_id: [u8; 32],
    /// Whether this is a propose / approve / reject action.
    pub vote_type: VoteType,
    /// Anti-double-vote tag. Uniquely determined by (secret, scope).
    pub nullifier: Nullifier,
}

impl ProofJournal {
    /// Canonical byte encoding. Used both by the guest (to commit) and by the
    /// verifier (to decode the receipt journal).
    pub fn to_bytes(&self) -> Vec<u8> {
        borsh::to_vec(self).expect("ProofJournal borsh encoding")
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, borsh::io::Error> {
        borsh::from_slice(bytes)
    }
}

/// Hash two Merkle children into a parent.
pub fn hash_pair(left: &[u8; 32], right: &[u8; 32]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"NODE");
    h.update(left);
    h.update(right);
    h.finalize().into()
}

/// Hash a leaf commitment. Domain-separated from internal nodes so a leaf
/// value can never be interpreted as a branch value.
pub fn hash_leaf(commitment: &Commitment) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"LEAF");
    h.update(commitment);
    h.finalize().into()
}

/// Derive a commitment from a member secret.
///
/// `view_salt` lets a member rotate their commitment without rotating the
/// underlying secret — useful for key hygiene across multiple multisigs.
pub fn commitment_from_secret(secret: &[u8; 32], view_salt: &[u8; 32]) -> Commitment {
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG);
    h.update(b"COMMIT");
    h.update(secret);
    h.update(view_salt);
    h.finalize().into()
}

/// Derive the proposal_id that scopes nullifiers for a given proposal.
///
/// Binding to (create_key, proposal_index) means a nullifier minted for
/// proposal N cannot be replayed on proposal M in the same multisig, or on
/// any proposal in a different multisig.
pub fn proposal_id(create_key: &[u8; 32], proposal_index: u64) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG);
    h.update(b"PROPOSAL");
    h.update(create_key);
    h.update(&proposal_index.to_be_bytes());
    h.finalize().into()
}

/// Derive the nullifier a given secret must produce for a given scope.
///
/// The circuit enforces nullifier == this, so the public on-chain check
/// `nullifier not in used_set` (across both approval and rejection
/// buckets) is sufficient to prevent any second vote from the same
/// member on the same proposal — whether they try Approve, Reject, or
/// re-Propose.
pub fn nullifier_from_secret(
    secret: &[u8; 32],
    proposal_id: &[u8; 32],
    create_key: &[u8; 32],
) -> Nullifier {
    let mut h = Sha256::new();
    h.update(DOMAIN_TAG);
    h.update(b"NULLIFIER");
    h.update(secret);
    h.update(proposal_id);
    h.update(create_key);
    h.finalize().into()
}

/// Verify a Merkle path leads from a leaf commitment to a claimed root.
///
/// `path_bits` is the leaf index: bit i (LSB first) says whether the sibling
/// at level i is on the right (0) or left (1).
pub fn verify_merkle_path(
    commitment: &Commitment,
    path_bits: u32,
    siblings: &[[u8; 32]; MERKLE_DEPTH],
    expected_root: &MerkleRoot,
) -> bool {
    let mut node = hash_leaf(commitment);
    for level in 0..MERKLE_DEPTH {
        let sibling = &siblings[level];
        let bit = (path_bits >> level) & 1;
        node = if bit == 0 {
            hash_pair(&node, sibling)
        } else {
            hash_pair(sibling, &node)
        };
    }
    &node == expected_root
}

/// Verify that `old_leaf` is at slot `path_bits` under `expected_root`,
/// and simultaneously compute the new root that results from replacing
/// `old_leaf` with `new_leaf` at the same slot, leaving all siblings
/// untouched.
///
/// Returns `Some(new_root)` if `old_leaf` was indeed at that slot,
/// `None` otherwise.
///
/// This is the witnessed-update primitive that gates config-action
/// execution: AddMember verifies `old_leaf = EMPTY_LEAF`, RemoveMember
/// verifies `old_leaf = target_commitment`. Without this check a
/// malicious proposer can install an `expected_new_root` that drops
/// legitimate members.
pub fn verify_and_replace(
    old_leaf: &Commitment,
    new_leaf: &Commitment,
    path_bits: u32,
    siblings: &[[u8; 32]; MERKLE_DEPTH],
    expected_root: &MerkleRoot,
) -> Option<MerkleRoot> {
    let mut old_node = hash_leaf(old_leaf);
    let mut new_node = hash_leaf(new_leaf);
    for level in 0..MERKLE_DEPTH {
        let sibling = &siblings[level];
        let bit = (path_bits >> level) & 1;
        if bit == 0 {
            old_node = hash_pair(&old_node, sibling);
            new_node = hash_pair(&new_node, sibling);
        } else {
            old_node = hash_pair(sibling, &old_node);
            new_node = hash_pair(sibling, &new_node);
        }
    }
    if &old_node == expected_root {
        Some(new_node)
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commitment_is_deterministic() {
        let sk = [7u8; 32];
        let salt = [3u8; 32];
        assert_eq!(commitment_from_secret(&sk, &salt), commitment_from_secret(&sk, &salt));
    }

    #[test]
    fn nullifier_does_not_depend_on_vote_type() {
        // Same member, same proposal: vote_type is NOT in the preimage,
        // so Approve and Reject produce the same nullifier. This is what
        // makes `nullifier_used` (checking both buckets) sufficient to
        // catch "approve then also reject" from the same member.
        let sk = [1u8; 32];
        let ck = [2u8; 32];
        let pid = proposal_id(&ck, 1);
        let n = nullifier_from_secret(&sk, &pid, &ck);
        // Just confirm determinism — no separate VoteType arg to vary.
        assert_eq!(n, nullifier_from_secret(&sk, &pid, &ck));
    }

    #[test]
    fn nullifier_differs_per_proposal() {
        let sk = [1u8; 32];
        let ck = [2u8; 32];
        let n1 = nullifier_from_secret(&sk, &proposal_id(&ck, 1), &ck);
        let n2 = nullifier_from_secret(&sk, &proposal_id(&ck, 2), &ck);
        assert_ne!(n1, n2);
    }

    #[test]
    fn nullifier_differs_per_multisig() {
        let sk = [1u8; 32];
        let ck_a = [2u8; 32];
        let ck_b = [9u8; 32];
        let n_a = nullifier_from_secret(&sk, &proposal_id(&ck_a, 1), &ck_a);
        let n_b = nullifier_from_secret(&sk, &proposal_id(&ck_b, 1), &ck_b);
        assert_ne!(n_a, n_b);
    }

    #[test]
    fn verify_and_replace_accepts_valid_swap() {
        // Build a two-leaf tree with `old_leaf` at slot 0, then check
        // that swapping it for `new_leaf` produces the same root we'd
        // get by building the tree from scratch with `new_leaf`.
        let old_leaf: Commitment = [11u8; 32];
        let new_leaf: Commitment = [22u8; 32];
        let other: Commitment = [33u8; 32];

        let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
        // Sibling at level 0 is the other leaf, hashed. Levels above
        // are the empty-subtree zeros (start at hash_leaf(EMPTY_LEAF)).
        siblings[0] = hash_leaf(&other);
        let empty_l0 = hash_leaf(&EMPTY_LEAF);
        let mut cur_empty = empty_l0;
        for s in siblings.iter_mut().skip(1) {
            cur_empty = hash_pair(&cur_empty, &cur_empty);
            *s = cur_empty;
        }

        // Root with old_leaf at slot 0.
        let mut node = hash_leaf(&old_leaf);
        for s in siblings.iter() {
            node = hash_pair(&node, s);
        }
        let old_root = node;

        // verify_and_replace should accept the swap.
        let new_root = verify_and_replace(&old_leaf, &new_leaf, 0, &siblings, &old_root)
            .expect("witnessed swap should verify");

        // The result must match a directly-computed root for new_leaf at slot 0.
        let mut node2 = hash_leaf(&new_leaf);
        for s in siblings.iter() {
            node2 = hash_pair(&node2, s);
        }
        assert_eq!(new_root, node2);
    }

    #[test]
    fn verify_and_replace_rejects_wrong_old_leaf() {
        let old_leaf: Commitment = [11u8; 32];
        let claimed_old: Commitment = [99u8; 32]; // wrong
        let new_leaf: Commitment = [22u8; 32];

        let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
        let empty_l0 = hash_leaf(&EMPTY_LEAF);
        let mut cur_empty = empty_l0;
        siblings[0] = empty_l0;
        for s in siblings.iter_mut().skip(1) {
            cur_empty = hash_pair(&cur_empty, &cur_empty);
            *s = cur_empty;
        }

        let mut node = hash_leaf(&old_leaf);
        for s in siblings.iter() {
            node = hash_pair(&node, s);
        }
        let root = node;

        // Prover lies about what's currently at the slot.
        let res = verify_and_replace(&claimed_old, &new_leaf, 0, &siblings, &root);
        assert!(res.is_none(), "wrong old_leaf must be rejected");
    }
}
