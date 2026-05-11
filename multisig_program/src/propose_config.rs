//! Propose a config change (add member, remove member, change threshold).
//!
//! Authenticated by a membership ZK proof with `vote_type = Approve`
//! (propose counts as the proposer's first approval; see `propose.rs`).
//!
//! For AddMember / RemoveMember the proposer must additionally supply a
//! Merkle witness `(target_path_bits, siblings)` that proves what
//! currently sits at the target slot under `state.members_root`. The
//! handler recomputes the new root that results from the proposed swap
//! and asserts it equals the `expected_new_root` carried by the action.
//! Without this check a malicious proposer could install an arbitrary
//! root once threshold approves — see F-1 in the review.
//!
//! At execute time we don't re-verify the witness: `stale_transaction_index`
//! guarantees that if a proposal is still active, no config change has
//! executed since it was created, so `state.members_root` is unchanged
//! and the propose-time check is still binding.
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA (mut, bumps transaction_index)
//! - accounts[1]: proposal PDA (init, uninitialized)

use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::ChainedCall;
use multisig_core::{
    ConfigAction, MembershipJournal, MultisigState, Proposal,
};
use zk_common::{
    proposal_id as derive_proposal_id, verify_and_replace, VoteType, EMPTY_LEAF, MERKLE_DEPTH,
};

use crate::verify::verify_and_decode;

/// Witness for the proposed leaf swap. Required for AddMember and
/// RemoveMember; ignored (and pass `None`) for ChangeThreshold.
pub type SwapWitness = (u32, [[u8; 32]; MERKLE_DEPTH]);

pub fn handle(
    accounts: &[AccountWithMetadata],
    config_action: ConfigAction,
    swap_witness: Option<SwapWitness>,
    proposal_index_arg: u64,
    membership_journal: &MembershipJournal,
) -> (Vec<Account>, Vec<ChainedCall>) {
    assert!(
        accounts.len() >= 2,
        "ProposeConfig requires multisig_state + proposal accounts"
    );
    let multisig_account = &accounts[0];
    let proposal_account = &accounts[1];

    assert!(
        proposal_account.account == Account::default(),
        "Proposal account must be uninitialized"
    );

    let state_data: Vec<u8> = multisig_account.account.data.clone().into();
    let mut state: MultisigState =
        borsh::from_slice(&state_data).expect("Failed to deserialize multisig state");

    match &config_action {
        ConfigAction::AddMember {
            new_commitment,
            target_path_bits,
            expected_new_root,
        } => {
            assert!(state.member_count < u8::MAX, "member_count would overflow");
            assert!(
                new_commitment != &EMPTY_LEAF,
                "new_commitment must not equal EMPTY_LEAF"
            );
            let (witness_path, witness_siblings) = swap_witness
                .as_ref()
                .expect("AddMember requires a swap_witness");
            assert_eq!(
                *witness_path, *target_path_bits,
                "swap_witness path does not match config_action target_path_bits"
            );
            // Slot must currently be empty; recompute the post-add root.
            let recomputed = verify_and_replace(
                &EMPTY_LEAF,
                new_commitment,
                *target_path_bits,
                witness_siblings,
                &state.members_root,
            )
            .expect("AddMember: target slot is not currently EMPTY_LEAF under members_root");
            assert_eq!(
                &recomputed, expected_new_root,
                "AddMember: expected_new_root does not match the witnessed swap"
            );
        }
        ConfigAction::RemoveMember {
            target_commitment,
            target_path_bits,
            expected_new_root,
        } => {
            assert!(
                state.member_count > state.threshold,
                "Removing would make count fall below threshold"
            );
            assert!(
                target_commitment != &EMPTY_LEAF,
                "target_commitment must not equal EMPTY_LEAF"
            );
            let (witness_path, witness_siblings) = swap_witness
                .as_ref()
                .expect("RemoveMember requires a swap_witness");
            assert_eq!(
                *witness_path, *target_path_bits,
                "swap_witness path does not match config_action target_path_bits"
            );
            // Slot must currently hold target_commitment; recompute the post-remove root.
            let recomputed = verify_and_replace(
                target_commitment,
                &EMPTY_LEAF,
                *target_path_bits,
                witness_siblings,
                &state.members_root,
            )
            .expect("RemoveMember: target slot does not currently hold target_commitment");
            assert_eq!(
                &recomputed, expected_new_root,
                "RemoveMember: expected_new_root does not match the witnessed swap"
            );
        }
        ConfigAction::ChangeThreshold { new_threshold } => {
            assert!(*new_threshold >= 1, "Threshold must be at least 1");
            assert!(
                *new_threshold <= state.member_count,
                "Threshold cannot exceed member count"
            );
            assert!(
                swap_witness.is_none(),
                "ChangeThreshold must not carry a swap_witness"
            );
        }
    }

    let next_index = state.next_proposal_index();
    assert_eq!(
        next_index, proposal_index_arg,
        "proposal_index arg does not match next transaction_index"
    );

    let journal = verify_and_decode(membership_journal);

    assert_eq!(journal.multisig_create_key, state.create_key);
    assert_eq!(
        journal.members_root, state.members_root,
        "Proof was generated against a different member set"
    );
    let expected_pid = derive_proposal_id(&state.create_key, next_index);
    assert_eq!(journal.proposal_id, expected_pid);
    assert_eq!(
        journal.vote_type,
        VoteType::Approve,
        "Config proposal requires Approve vote_type (propose is the proposer's first approval)"
    );

    let proposal = Proposal::new_config(
        next_index,
        state.create_key,
        state.members_root,
        config_action,
        journal.nullifier,
    );

    let state_bytes = borsh::to_vec(&state).unwrap();
    let mut multisig_post = multisig_account.account.clone();
    multisig_post.data = state_bytes.try_into().unwrap();

    let proposal_bytes = borsh::to_vec(&proposal).unwrap();
    let mut proposal_post = Account::default();
    proposal_post.data = proposal_bytes.try_into().unwrap();

    (vec![multisig_post, proposal_post], vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use nssa_core::account::AccountId;
    use zk_common::{hash_leaf, hash_pair, ProofJournal};

    fn make_account(id: &[u8; 32], data: Vec<u8>) -> AccountWithMetadata {
        let mut account = Account::default();
        account.data = data.try_into().unwrap();
        AccountWithMetadata {
            account_id: AccountId::new(*id),
            account,
            is_authorized: false,
        }
    }

    fn state_bytes(ck: [u8; 32], root: [u8; 32], threshold: u8, count: u8) -> Vec<u8> {
        borsh::to_vec(&MultisigState::new(ck, threshold, count, root)).unwrap()
    }

    fn journal(ck: [u8; 32], root: [u8; 32], idx: u64, null: [u8; 32]) -> Vec<u8> {
        let j = ProofJournal {
            members_root: root,
            multisig_create_key: ck,
            proposal_id: derive_proposal_id(&ck, idx),
            vote_type: VoteType::Approve,
            nullifier: null,
        };
        borsh::to_vec(&j).unwrap()
    }

    /// Returns `(siblings, all_empty_root)` for the all-empty tree —
    /// every sibling level is the next-level zero hash.
    fn empty_tree() -> ([[u8; 32]; MERKLE_DEPTH], [u8; 32]) {
        let mut siblings = [[0u8; 32]; MERKLE_DEPTH];
        let mut cur = hash_leaf(&EMPTY_LEAF);
        siblings[0] = cur;
        for s in siblings.iter_mut().skip(1) {
            cur = hash_pair(&cur, &cur);
            *s = cur;
        }
        // Root of an all-empty tree is hash_pair applied MERKLE_DEPTH times.
        let mut root = hash_leaf(&EMPTY_LEAF);
        for _ in 0..MERKLE_DEPTH {
            root = hash_pair(&root, &root);
        }
        (siblings, root)
    }

    /// Compute the root that results from placing `leaf` (already a
    /// commitment to be `hash_leaf`'d) at the given path in an
    /// otherwise-empty tree.
    fn root_with_leaf_at(leaf: &[u8; 32], path_bits: u32, siblings: &[[u8; 32]; MERKLE_DEPTH]) -> [u8; 32] {
        let mut node = hash_leaf(leaf);
        for level in 0..MERKLE_DEPTH {
            let bit = (path_bits >> level) & 1;
            if bit == 0 {
                node = hash_pair(&node, &siblings[level]);
            } else {
                node = hash_pair(&siblings[level], &node);
            }
        }
        node
    }

    #[test]
    fn propose_add_member_with_witness() {
        let ck = [1u8; 32];
        let (siblings, root) = empty_tree();
        let new_commitment = [5u8; 32];
        let path_bits = 0u32; // slot 0
        let expected_new_root = root_with_leaf_at(&new_commitment, path_bits, &siblings);

        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root, 2, 3)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root, 1, [9u8; 32]);
        let action = ConfigAction::AddMember {
            new_commitment,
            target_path_bits: path_bits,
            expected_new_root,
        };
        let (out, _) = handle(&accounts, action.clone(), Some((path_bits, siblings)), 1, &j);
        let p: Proposal = borsh::from_slice(&Vec::from(out[1].data.clone())).unwrap();
        assert_eq!(p.config_action, Some(action));
    }

    #[test]
    #[should_panic(expected = "expected_new_root does not match the witnessed swap")]
    fn propose_add_member_wrong_expected_root_rejected() {
        let ck = [1u8; 32];
        let (siblings, root) = empty_tree();
        let path_bits = 0u32;
        // Proposer lies: claims expected_new_root is something other
        // than the verified swap result.
        let action = ConfigAction::AddMember {
            new_commitment: [5u8; 32],
            target_path_bits: path_bits,
            expected_new_root: [0xAAu8; 32],
        };
        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root, 2, 3)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root, 1, [9u8; 32]);
        handle(&accounts, action, Some((path_bits, siblings)), 1, &j);
    }

    #[test]
    #[should_panic(expected = "target slot is not currently EMPTY_LEAF")]
    fn propose_add_member_into_occupied_slot_rejected() {
        let ck = [1u8; 32];
        // Build a tree where slot 0 is occupied by commitment_a.
        let commitment_a = [11u8; 32];
        let (siblings, _empty_root) = empty_tree();
        let path_bits = 0u32;
        let root_with_a = root_with_leaf_at(&commitment_a, path_bits, &siblings);

        // Proposer tries to "AddMember" at slot 0, but the slot already
        // holds commitment_a.
        let action = ConfigAction::AddMember {
            new_commitment: [22u8; 32],
            target_path_bits: path_bits,
            expected_new_root: [0xBBu8; 32], // doesn't matter; witness check fires first
        };
        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root_with_a, 2, 3)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root_with_a, 1, [9u8; 32]);
        handle(&accounts, action, Some((path_bits, siblings)), 1, &j);
    }

    #[test]
    #[should_panic(expected = "new_commitment must not equal EMPTY_LEAF")]
    fn propose_add_member_empty_leaf_as_commitment_rejected() {
        let ck = [1u8; 32];
        let (siblings, root) = empty_tree();
        let path_bits = 0u32;
        let action = ConfigAction::AddMember {
            new_commitment: EMPTY_LEAF,
            target_path_bits: path_bits,
            expected_new_root: root,
        };
        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root, 2, 3)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root, 1, [9u8; 32]);
        handle(&accounts, action, Some((path_bits, siblings)), 1, &j);
    }

    #[test]
    fn propose_remove_member_with_witness() {
        let ck = [1u8; 32];
        // Build a tree where slot 3 holds commitment_a.
        let commitment_a = [11u8; 32];
        let (siblings, _empty_root) = empty_tree();
        let path_bits = 3u32;
        let root_with_a = root_with_leaf_at(&commitment_a, path_bits, &siblings);
        // After removal, slot 3 holds EMPTY_LEAF — that's the all-empty tree root.
        let expected_new_root = root_with_leaf_at(&EMPTY_LEAF, path_bits, &siblings);

        let action = ConfigAction::RemoveMember {
            target_commitment: commitment_a,
            target_path_bits: path_bits,
            expected_new_root,
        };
        let accounts = vec![
            // member_count=3, threshold=2 so remove is allowed.
            make_account(&[10u8; 32], state_bytes(ck, root_with_a, 2, 3)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root_with_a, 1, [9u8; 32]);
        let (out, _) = handle(&accounts, action.clone(), Some((path_bits, siblings)), 1, &j);
        let p: Proposal = borsh::from_slice(&Vec::from(out[1].data.clone())).unwrap();
        assert_eq!(p.config_action, Some(action));
    }

    #[test]
    #[should_panic(expected = "target slot does not currently hold target_commitment")]
    fn propose_remove_member_wrong_target_rejected() {
        let ck = [1u8; 32];
        let commitment_a = [11u8; 32];
        let (siblings, _) = empty_tree();
        let path_bits = 3u32;
        let root_with_a = root_with_leaf_at(&commitment_a, path_bits, &siblings);

        // Proposer claims to remove a different commitment at the same slot.
        let action = ConfigAction::RemoveMember {
            target_commitment: [99u8; 32],
            target_path_bits: path_bits,
            expected_new_root: [0xCCu8; 32],
        };
        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root_with_a, 2, 3)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root_with_a, 1, [9u8; 32]);
        handle(&accounts, action, Some((path_bits, siblings)), 1, &j);
    }

    #[test]
    #[should_panic(expected = "below threshold")]
    fn remove_below_threshold_rejected_at_propose_time() {
        let ck = [1u8; 32];
        let commitment_a = [11u8; 32];
        let (siblings, _) = empty_tree();
        let path_bits = 0u32;
        let root_with_a = root_with_leaf_at(&commitment_a, path_bits, &siblings);
        let expected_new_root = root_with_leaf_at(&EMPTY_LEAF, path_bits, &siblings);

        // member_count=2, threshold=2: remove would drop below threshold.
        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root_with_a, 2, 2)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root_with_a, 1, [9u8; 32]);
        let action = ConfigAction::RemoveMember {
            target_commitment: commitment_a,
            target_path_bits: path_bits,
            expected_new_root,
        };
        handle(&accounts, action, Some((path_bits, siblings)), 1, &j);
    }

    #[test]
    fn propose_change_threshold_takes_no_witness() {
        let ck = [1u8; 32];
        let (_, root) = empty_tree();
        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root, 2, 3)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root, 1, [9u8; 32]);
        let action = ConfigAction::ChangeThreshold { new_threshold: 3 };
        let (out, _) = handle(&accounts, action.clone(), None, 1, &j);
        let p: Proposal = borsh::from_slice(&Vec::from(out[1].data.clone())).unwrap();
        assert_eq!(p.config_action, Some(action));
    }

    #[test]
    #[should_panic(expected = "ChangeThreshold must not carry a swap_witness")]
    fn change_threshold_with_witness_rejected() {
        let ck = [1u8; 32];
        let (siblings, root) = empty_tree();
        let accounts = vec![
            make_account(&[10u8; 32], state_bytes(ck, root, 2, 3)),
            make_account(&[20u8; 32], vec![]),
        ];
        let j = journal(ck, root, 1, [9u8; 32]);
        let action = ConfigAction::ChangeThreshold { new_threshold: 3 };
        handle(&accounts, action, Some((0, siblings)), 1, &j);
    }
}
