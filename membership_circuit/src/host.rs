//! Host-only helpers: append-only Merkle tree + Risc0 proof builder.
//!
//! - `IncrementalMerkleTree` — keeps the full member set; used to generate
//!   the sibling path for a given commitment.
//! - `ProofBuilder` — wires up the guest ELF with `default_prover()` and
//!   returns a `Receipt`.
//! - `GuestInput` — wire format, must stay byte-identical with the
//!   definition in `guest/src/main.rs`.

use std::collections::HashMap;

use borsh::{BorshDeserialize, BorshSerialize};
use risc0_zkvm::{default_prover, ExecutorEnv, Receipt};
use zk_common::{
    commitment_from_secret, hash_leaf, hash_pair, Commitment, MerkleRoot, VoteType, EMPTY_LEAF,
    MERKLE_DEPTH,
};

use crate::MEMBERSHIP_PROOF_ELF;

// ---------------------------------------------------------------------------
// Guest input — must stay byte-identical with the one defined in the guest.
// ---------------------------------------------------------------------------

#[derive(BorshSerialize, BorshDeserialize)]
pub struct GuestInput {
    pub secret: [u8; 32],
    pub view_salt: [u8; 32],
    pub path_bits: u32,
    pub siblings: [[u8; 32]; MERKLE_DEPTH],
    pub members_root: MerkleRoot,
    pub multisig_create_key: [u8; 32],
    pub proposal_index: u64,
    pub vote_type: VoteType,
}

// ---------------------------------------------------------------------------
// Incremental Merkle tree
// ---------------------------------------------------------------------------

/// An append-only Merkle tree of fixed depth `MERKLE_DEPTH`.
/// Storage is sparse — only filled subtrees are kept in a map.
pub struct IncrementalMerkleTree {
    /// `(level, index) -> node_hash`. Level 0 = leaves (already hashed with
    /// the LEAF domain tag). Missing entries are interpreted as `zero[level]`.
    nodes: HashMap<(u8, u64), [u8; 32]>,
    /// Pre-computed hashes for all-empty subtrees, by level.
    zeros: Vec<[u8; 32]>,
    /// Next free leaf slot.
    next_index: u64,
    /// Reverse lookup: commitment -> leaf index (for proof generation).
    leaf_index_of: HashMap<Commitment, u64>,
}

impl Default for IncrementalMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

impl IncrementalMerkleTree {
    pub fn new() -> Self {
        let mut zeros = Vec::with_capacity(MERKLE_DEPTH + 1);
        let mut cur = hash_leaf(&EMPTY_LEAF);
        zeros.push(cur);
        for _ in 0..MERKLE_DEPTH {
            cur = hash_pair(&cur, &cur);
            zeros.push(cur);
        }
        Self {
            nodes: HashMap::new(),
            zeros,
            next_index: 0,
            leaf_index_of: HashMap::new(),
        }
    }

    pub fn capacity() -> u64 {
        1u64 << MERKLE_DEPTH
    }

    pub fn len(&self) -> u64 {
        self.next_index
    }

    pub fn is_empty(&self) -> bool {
        self.next_index == 0
    }

    /// Append a member commitment. Returns the leaf index.
    pub fn insert(&mut self, commitment: Commitment) -> u64 {
        assert!(self.next_index < Self::capacity(), "Merkle tree full");
        let idx = self.next_index;
        self.set_leaf(idx, hash_leaf(&commitment));
        self.leaf_index_of.insert(commitment, idx);
        self.next_index += 1;
        idx
    }

    /// Remove a commitment by overwriting its leaf with `hash_leaf(EMPTY_LEAF)`.
    /// Does not compact — the slot stays unusable for append.
    pub fn remove(&mut self, commitment: &Commitment) -> bool {
        let Some(idx) = self.leaf_index_of.remove(commitment) else {
            return false;
        };
        self.set_leaf(idx, hash_leaf(&EMPTY_LEAF));
        true
    }

    pub fn contains(&self, commitment: &Commitment) -> bool {
        self.leaf_index_of.contains_key(commitment)
    }

    pub fn root(&self) -> MerkleRoot {
        self.node(MERKLE_DEPTH as u8, 0)
    }

    /// Return the sibling path + leaf index for a commitment.
    /// Returns `None` if the commitment isn't present.
    pub fn proof(&self, commitment: &Commitment) -> Option<(u32, [[u8; 32]; MERKLE_DEPTH])> {
        let idx = *self.leaf_index_of.get(commitment)?;
        Some(self.proof_for_index(idx))
    }

    /// Return the sibling path for the leaf at `leaf_index`, regardless
    /// of whether it currently holds a commitment or `EMPTY_LEAF`.
    ///
    /// Used by config-change proposals (AddMember witnesses an empty
    /// slot; RemoveMember witnesses a specific commitment at its slot).
    /// Panics if `leaf_index` is out of range.
    pub fn proof_for_index(&self, leaf_index: u64) -> (u32, [[u8; 32]; MERKLE_DEPTH]) {
        assert!(
            leaf_index < Self::capacity(),
            "leaf_index out of range: {leaf_index} >= {}",
            Self::capacity()
        );
        let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
        let mut cur = leaf_index;
        for lvl in 0..MERKLE_DEPTH {
            let sibling_idx = cur ^ 1;
            siblings[lvl] = self.node(lvl as u8, sibling_idx);
            cur >>= 1;
        }
        let path_bits: u32 = (leaf_index as u32) & ((1u32 << MERKLE_DEPTH) - 1);
        (path_bits, siblings)
    }

    /// Return the index of the next free (empty) leaf slot. AddMember
    /// proposers use this to pick a `target_path_bits` for the witness.
    pub fn next_free_index(&self) -> u64 {
        self.next_index
    }

    /// Look up the leaf index for a commitment. RemoveMember proposers
    /// use this to pin the witness to the right slot.
    pub fn index_of(&self, commitment: &Commitment) -> Option<u64> {
        self.leaf_index_of.get(commitment).copied()
    }

    fn node(&self, level: u8, index: u64) -> [u8; 32] {
        if let Some(v) = self.nodes.get(&(level, index)) {
            return *v;
        }
        self.zeros[level as usize]
    }

    fn set_leaf(&mut self, leaf_idx: u64, leaf_hash: [u8; 32]) {
        self.nodes.insert((0, leaf_idx), leaf_hash);
        let mut cur = leaf_idx;
        let mut cur_hash = leaf_hash;
        for lvl in 0..MERKLE_DEPTH {
            let sibling_idx = cur ^ 1;
            let sibling = self.node(lvl as u8, sibling_idx);
            let (left, right) = if cur & 1 == 0 {
                (cur_hash, sibling)
            } else {
                (sibling, cur_hash)
            };
            let parent = hash_pair(&left, &right);
            cur >>= 1;
            self.nodes.insert(((lvl + 1) as u8, cur), parent);
            cur_hash = parent;
        }
    }
}

// ---------------------------------------------------------------------------
// Proof builder
// ---------------------------------------------------------------------------

/// Host-side helper: given a member's secret + their Merkle position,
/// produce a Risc0 receipt the on-chain program can verify.
pub struct ProofBuilder<'a> {
    pub tree: &'a IncrementalMerkleTree,
    pub secret: [u8; 32],
    pub view_salt: [u8; 32],
    pub multisig_create_key: [u8; 32],
}

impl<'a> ProofBuilder<'a> {
    /// Generate a receipt for a given (proposal_index, vote_type).
    /// Blocks on proving — call off the hot path.
    pub fn build(&self, proposal_index: u64, vote_type: VoteType) -> anyhow::Result<Receipt> {
        let commitment = commitment_from_secret(&self.secret, &self.view_salt);
        let (path_bits, siblings) = self
            .tree
            .proof(&commitment)
            .ok_or_else(|| anyhow::anyhow!("commitment not in tree"))?;

        let input = GuestInput {
            secret: self.secret,
            view_salt: self.view_salt,
            path_bits,
            siblings,
            members_root: self.tree.root(),
            multisig_create_key: self.multisig_create_key,
            proposal_index,
            vote_type,
        };
        let input_bytes = borsh::to_vec(&input)?;

        let env = ExecutorEnv::builder().write(&input_bytes)?.build()?;
        let prover = default_prover();
        let prove_info = prover.prove(env, MEMBERSHIP_PROOF_ELF)?;
        Ok(prove_info.receipt)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use zk_common::{commitment_from_secret, verify_merkle_path};

    #[test]
    fn insert_and_prove_roundtrip() {
        let mut tree = IncrementalMerkleTree::new();
        let sk_a = [1u8; 32];
        let sk_b = [2u8; 32];
        let salt = [7u8; 32];
        let c_a = commitment_from_secret(&sk_a, &salt);
        let c_b = commitment_from_secret(&sk_b, &salt);
        tree.insert(c_a);
        tree.insert(c_b);

        let root = tree.root();
        let (path_bits_a, siblings_a) = tree.proof(&c_a).unwrap();
        assert!(verify_merkle_path(&c_a, path_bits_a, &siblings_a, &root));

        let (path_bits_b, siblings_b) = tree.proof(&c_b).unwrap();
        assert!(verify_merkle_path(&c_b, path_bits_b, &siblings_b, &root));
    }

    #[test]
    fn remove_invalidates_old_proof() {
        let mut tree = IncrementalMerkleTree::new();
        let salt = [7u8; 32];
        let sk = [3u8; 32];
        let c = commitment_from_secret(&sk, &salt);
        tree.insert(c);
        let (pb, sb) = tree.proof(&c).unwrap();
        let old_root = tree.root();
        assert!(verify_merkle_path(&c, pb, &sb, &old_root));

        tree.remove(&c);
        assert_ne!(tree.root(), old_root);
        assert!(!verify_merkle_path(&c, pb, &sb, &tree.root()));
    }

    #[test]
    fn empty_tree_has_stable_root() {
        let a = IncrementalMerkleTree::new();
        let b = IncrementalMerkleTree::new();
        assert_eq!(a.root(), b.root());
    }
}
