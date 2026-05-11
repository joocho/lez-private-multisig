//! Private lez-multisig core types.
//!
//! Design deltas vs. the public lez-multisig:
//!
//! - `MultisigState.members: Vec<[u8;32]>` is replaced by `members_root` — a
//!   Merkle root over member commitments. Members are never named on-chain.
//! - `Proposal.approved / rejected: Vec<[u8;32]>` (identity-stamped) is
//!   replaced by `approval_nullifiers / rejection_nullifiers: Vec<[u8;32]>`
//!   — identity-opaque tags. Nullifier count is the vote count.
//! - Proposals don't record a `proposer` identity. Propose mints an
//!   `Approve`-type nullifier and seeds it into `approval_nullifiers`
//!   (proposer auto-approval), but the identity is not revealed.
//!   `vote_type` is intentionally NOT in the nullifier preimage — see
//!   `zk_common::VoteType` — so a subsequent `Approve` or `Reject` from
//!   the same member collides on the nullifier and is rejected
//!   (one-vote-per-member per proposal across propose/approve/reject).
//! - `stale_transaction_index` is lifted straight from Squads v4: config
//!   changes bump it, which invalidates all pending proposals. This closes
//!   the "stale approvals from removed members" hole (H2 in the audit of
//!   the public version).
//! - Config actions that change the Merkle tree (`AddMember`,
//!   `RemoveMember`) carry a witnessed root transition: the proposer
//!   supplies a Merkle path for the target slot, and `propose_config`
//!   recomputes the new root and asserts it equals `expected_new_root`.
//!   Without this check a malicious proposer could install an arbitrary
//!   tree on threshold approval.

use borsh::{BorshDeserialize, BorshSerialize};
use nssa_core::program::ProgramId;
use serde::{Deserialize, Serialize};
use zk_common::{MerkleRoot, Nullifier, MERKLE_DEPTH};

// ---------------------------------------------------------------------------
// Instructions
// ---------------------------------------------------------------------------

/// Borsh-encoded `ProofJournal`. The inner Risc0 receipt that proves this
/// journal is NOT carried in the instruction — it is supplied out-of-band
/// to the LEZ prover as a Risc0 *assumption*. Inside the outer LEZ guest,
/// `risc0_zkvm::guest::env::verify(MEMBERSHIP_PROOF_ID, journal_bytes)`
/// consumes that assumption, which is cryptographically equivalent to
/// verifying a nested receipt but much cheaper in instruction payload.
pub type MembershipJournal = Vec<u8>;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Instruction {
    /// Create a new multisig with M-of-N threshold.
    /// The creator publishes the members' Merkle root; no member accounts
    /// are claimed, no identities are listed on-chain.
    CreateMultisig {
        create_key: [u8; 32],
        threshold: u8,
        member_count: u8,
        members_root: MerkleRoot,
    },

    /// Propose a target-program ChainedCall, authenticated by a membership
    /// proof with `vote_type = Approve` (propose counts as the proposer's
    /// first approval). The proposer's nullifier is seeded into the
    /// proposal's approval set; a subsequent `Approve` from the same
    /// member collides on the nullifier and is rejected.
    Propose {
        target_program_id: ProgramId,
        target_instruction_data: Vec<u32>,
        target_account_count: u8,
        pda_seeds: Vec<[u8; 32]>,
        authorized_indices: Vec<u8>,
        create_key: [u8; 32],
        proposal_index: u64,
        /// Risc0 receipt proving (membership, nullifier, Propose scope).
        membership_journal: MembershipJournal,
    },

    Approve {
        create_key: [u8; 32],
        proposal_index: u64,
        membership_journal: MembershipJournal,
    },

    Reject {
        create_key: [u8; 32],
        proposal_index: u64,
        membership_journal: MembershipJournal,
    },

    /// Execute is unauthenticated — any relayer can submit once the proposal
    /// has accumulated `threshold` approval nullifiers. Execution determinism
    /// + the fact that proposal contents are trusted on-chain means there's
    /// no benefit to gating execute on membership.
    Execute {
        create_key: [u8; 32],
        proposal_index: u64,
    },

    ProposeAddMember {
        new_commitment: [u8; 32],
        /// New Merkle root after inserting `new_commitment` at slot
        /// `target_path_bits`. Verified at propose time (see
        /// `propose_config::handle`) — handlers refuse to accept any
        /// root that isn't the witnessed transition from
        /// `state.members_root`.
        expected_new_root: MerkleRoot,
        /// Slot (bottom MERKLE_DEPTH bits) where `new_commitment` is
        /// being inserted. Must currently hold `EMPTY_LEAF`.
        target_path_bits: u32,
        /// Sibling path under `state.members_root` for the target slot.
        siblings: [[u8; 32]; MERKLE_DEPTH],
        create_key: [u8; 32],
        proposal_index: u64,
        membership_journal: MembershipJournal,
    },

    ProposeRemoveMember {
        /// Commitment being removed. Target leaf becomes `EMPTY_LEAF`.
        target_commitment: [u8; 32],
        expected_new_root: MerkleRoot,
        /// Slot (bottom MERKLE_DEPTH bits) where `target_commitment`
        /// currently lives. Witnessed against `state.members_root`.
        target_path_bits: u32,
        siblings: [[u8; 32]; MERKLE_DEPTH],
        create_key: [u8; 32],
        proposal_index: u64,
        membership_journal: MembershipJournal,
    },

    ProposeChangeThreshold {
        new_threshold: u8,
        create_key: [u8; 32],
        proposal_index: u64,
        membership_journal: MembershipJournal,
    },
}

// ---------------------------------------------------------------------------
// Config action (embedded in config-change proposals)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ConfigAction {
    AddMember {
        new_commitment: [u8; 32],
        /// Slot the new commitment was inserted at. Recorded for off-chain
        /// indexing — the witness (siblings) is verified at propose time
        /// and intentionally NOT stored on-chain.
        target_path_bits: u32,
        expected_new_root: MerkleRoot,
    },
    RemoveMember {
        target_commitment: [u8; 32],
        /// Slot the removed commitment occupied (now `EMPTY_LEAF`).
        target_path_bits: u32,
        expected_new_root: MerkleRoot,
    },
    ChangeThreshold {
        new_threshold: u8,
    },
}

// ---------------------------------------------------------------------------
// Proposal
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, BorshSerialize, BorshDeserialize)]
pub enum ProposalStatus {
    Active,
    Executed,
    Rejected,
}

#[derive(Debug, Clone, BorshSerialize, BorshDeserialize)]
pub struct Proposal {
    pub index: u64,
    /// Pin this proposal to its parent multisig.
    pub multisig_create_key: [u8; 32],
    /// Members_root captured at propose time. All subsequent vote proofs
    /// must prove against this exact root (not the current one). This is
    /// what prevents a removed member from voting on in-flight proposals:
    /// once the root changes, their old commitment no longer verifies,
    /// and `stale_transaction_index` finishes the job.
    pub members_root_at_creation: MerkleRoot,

    // Target ChainedCall (for non-config proposals)
    pub target_program_id: ProgramId,
    pub target_instruction_data: Vec<u32>,
    pub target_account_count: u8,
    pub pda_seeds: Vec<[u8; 32]>,
    pub authorized_indices: Vec<u8>,

    // Voting state — identity-opaque
    pub approval_nullifiers: Vec<Nullifier>,
    pub rejection_nullifiers: Vec<Nullifier>,

    pub status: ProposalStatus,
    pub config_action: Option<ConfigAction>,
}

impl Proposal {
    /// Create a standard (ChainedCall) proposal. The propose-nullifier is
    /// seeded into `approval_nullifiers` so propose counts as auto-approve.
    #[allow(clippy::too_many_arguments)]
    pub fn new_standard(
        index: u64,
        multisig_create_key: [u8; 32],
        members_root_at_creation: MerkleRoot,
        target_program_id: ProgramId,
        target_instruction_data: Vec<u32>,
        target_account_count: u8,
        pda_seeds: Vec<[u8; 32]>,
        authorized_indices: Vec<u8>,
        propose_nullifier: Nullifier,
    ) -> Self {
        Self {
            index,
            multisig_create_key,
            members_root_at_creation,
            target_program_id,
            target_instruction_data,
            target_account_count,
            pda_seeds,
            authorized_indices,
            approval_nullifiers: vec![propose_nullifier],
            rejection_nullifiers: vec![],
            status: ProposalStatus::Active,
            config_action: None,
        }
    }

    pub fn new_config(
        index: u64,
        multisig_create_key: [u8; 32],
        members_root_at_creation: MerkleRoot,
        action: ConfigAction,
        propose_nullifier: Nullifier,
    ) -> Self {
        Self {
            index,
            multisig_create_key,
            members_root_at_creation,
            target_program_id: [0u32; 8],
            target_instruction_data: vec![],
            target_account_count: 0,
            pda_seeds: vec![],
            authorized_indices: vec![],
            approval_nullifiers: vec![propose_nullifier],
            rejection_nullifiers: vec![],
            status: ProposalStatus::Active,
            config_action: Some(action),
        }
    }

    /// True if `nullifier` already appears in either vote bucket.
    pub fn nullifier_used(&self, nullifier: &Nullifier) -> bool {
        self.approval_nullifiers.contains(nullifier)
            || self.rejection_nullifiers.contains(nullifier)
    }

    pub fn record_approval(&mut self, nullifier: Nullifier) {
        self.approval_nullifiers.push(nullifier);
    }

    pub fn record_rejection(&mut self, nullifier: Nullifier) {
        self.rejection_nullifiers.push(nullifier);
    }

    pub fn has_threshold(&self, threshold: u8) -> bool {
        self.approval_nullifiers.len() >= threshold as usize
    }

    pub fn is_dead(&self, threshold: u8, member_count: u8) -> bool {
        let remaining = (member_count as usize).saturating_sub(self.rejection_nullifiers.len());
        remaining < threshold as usize
    }
}

// ---------------------------------------------------------------------------
// MultisigState
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, BorshSerialize, BorshDeserialize)]
pub struct MultisigState {
    pub create_key: [u8; 32],
    pub threshold: u8,
    pub member_count: u8,
    /// Merkle root of member commitments (replaces the plaintext members vec).
    pub members_root: MerkleRoot,
    pub transaction_index: u64,
    /// Every proposal with `index <= stale_transaction_index` is stale
    /// (pre-config-change) and can no longer be voted or executed.
    pub stale_transaction_index: u64,
}

impl MultisigState {
    pub fn new(
        create_key: [u8; 32],
        threshold: u8,
        member_count: u8,
        members_root: MerkleRoot,
    ) -> Self {
        Self {
            create_key,
            threshold,
            member_count,
            members_root,
            transaction_index: 0,
            stale_transaction_index: 0,
        }
    }

    pub fn next_proposal_index(&mut self) -> u64 {
        self.transaction_index += 1;
        self.transaction_index
    }

    /// Called from any ConfigAction execute branch to retire pending
    /// proposals authored under the prior member set / threshold.
    pub fn bump_stale(&mut self) {
        self.stale_transaction_index = self.transaction_index;
    }

    pub fn is_stale(&self, proposal_index: u64) -> bool {
        proposal_index <= self.stale_transaction_index
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stale_index_bumps_to_current_tx_index() {
        let mut s = MultisigState::new([0u8; 32], 2, 3, [1u8; 32]);
        let _ = s.next_proposal_index(); // 1
        let _ = s.next_proposal_index(); // 2
        s.bump_stale();
        assert!(s.is_stale(1));
        assert!(s.is_stale(2));
        assert!(!s.is_stale(3));
    }

    #[test]
    fn has_threshold_counts_nullifiers() {
        let mut p = Proposal::new_standard(
            1,
            [0u8; 32],
            [0u8; 32],
            [0u32; 8],
            vec![],
            0,
            vec![],
            vec![],
            [9u8; 32],
        );
        assert_eq!(p.approval_nullifiers.len(), 1);
        assert!(!p.has_threshold(2));
        p.record_approval([8u8; 32]);
        assert!(p.has_threshold(2));
    }

    #[test]
    fn duplicate_nullifier_detected() {
        let p = Proposal::new_standard(
            1,
            [0u8; 32],
            [0u8; 32],
            [0u32; 8],
            vec![],
            0,
            vec![],
            vec![],
            [9u8; 32],
        );
        assert!(p.nullifier_used(&[9u8; 32]));
        assert!(!p.nullifier_used(&[7u8; 32]));
    }
}
