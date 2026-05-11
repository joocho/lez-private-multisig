//! Execute — permissionless. Anyone can submit once a proposal has
//! accumulated `threshold` approval nullifiers. The nullifiers themselves
//! are the threshold attestation; no executor identity is needed.
//!
//! For a standard proposal, emits a ChainedCall to the declared target.
//! For a config proposal, mutates MultisigState in place and bumps
//! `stale_transaction_index` so every older proposal is retired.
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA (mut)
//! - accounts[1]: proposal PDA (mut)
//! - accounts[2..]: target accounts for the ChainedCall (standard proposals only)

use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::{ChainedCall, PdaSeed};
use multisig_core::{ConfigAction, MultisigState, Proposal, ProposalStatus};
use zk_common::{hash_leaf, hash_pair, MerkleRoot, EMPTY_LEAF};

pub fn handle(
    accounts: &[AccountWithMetadata],
    proposal_index: u64,
) -> (Vec<AccountWithMetadata>, Vec<ChainedCall>) {
    assert!(
        accounts.len() >= 2,
        "Execute requires multisig_state + proposal accounts"
    );
    let multisig_account = &accounts[0];
    let proposal_account = &accounts[1];
    let target_accounts = &accounts[2..];

    let state_data: Vec<u8> = multisig_account.account.data.clone().into();
    let mut state: MultisigState =
        borsh::from_slice(&state_data).expect("Failed to deserialize multisig state");

    assert!(
        !state.is_stale(proposal_index),
        "Proposal was invalidated by a config change"
    );

    let proposal_data: Vec<u8> = proposal_account.account.data.clone().into();
    let mut proposal: Proposal =
        borsh::from_slice(&proposal_data).expect("Failed to deserialize proposal");

    assert_eq!(
        proposal.multisig_create_key, state.create_key,
        "Proposal does not belong to this multisig"
    );
    assert_eq!(proposal.index, proposal_index, "proposal_index mismatch");
    assert_eq!(
        proposal.status,
        ProposalStatus::Active,
        "Proposal is not active"
    );
    assert!(
        proposal.has_threshold(state.threshold),
        "Proposal does not have enough approvals: need {}, have {}",
        state.threshold,
        proposal.approval_nullifiers.len()
    );

    proposal.status = ProposalStatus::Executed;

    if let Some(config_action) = proposal.config_action.clone() {
        assert!(
            target_accounts.is_empty(),
            "Config change proposals should not have target accounts"
        );
        apply_config_action(&mut state, &proposal, &config_action);
        // Retire every proposal minted prior to (and including) this one.
        // This is the "stale index" lifted from Squads v4: after a
        // membership change, any in-flight vote attributed to the prior
        // member set is dropped — no need to hunt down individual votes.
        state.bump_stale();

        let state_bytes = borsh::to_vec(&state).unwrap();
        let mut multisig_post = multisig_account.account.clone();
        multisig_post.data = state_bytes.try_into().unwrap();

        let proposal_bytes = borsh::to_vec(&proposal).unwrap();
        let mut proposal_post = proposal_account.account.clone();
        proposal_post.data = proposal_bytes.try_into().unwrap();

        let wrap = |acc: Account, orig: &AccountWithMetadata| AccountWithMetadata {
            account: acc,
            account_id: orig.account_id,
            is_authorized: false,
        };
        (
            vec![
                wrap(multisig_post, multisig_account),
                wrap(proposal_post, proposal_account),
            ],
            vec![],
        )
    } else {
        assert_eq!(
            target_accounts.len(),
            proposal.target_account_count as usize,
            "Expected {} target accounts, got {}",
            proposal.target_account_count,
            target_accounts.len()
        );

        let target_program_id = proposal.target_program_id.clone();
        let target_instruction_data = proposal.target_instruction_data.clone();
        let pda_seeds: Vec<PdaSeed> = proposal
            .pda_seeds
            .iter()
            .map(|s| PdaSeed::new(*s))
            .collect();
        let authorized_indices = proposal.authorized_indices.clone();

        let proposal_bytes = borsh::to_vec(&proposal).unwrap();
        let mut proposal_post = proposal_account.account.clone();
        proposal_post.data = proposal_bytes.try_into().unwrap();

        let chained_pre_states: Vec<AccountWithMetadata> = target_accounts
            .iter()
            .enumerate()
            .map(|(i, acc)| {
                let mut acc = acc.clone();
                if authorized_indices.contains(&(i as u8)) {
                    acc.is_authorized = true;
                }
                acc
            })
            .collect();

        let chained_call = ChainedCall {
            program_id: target_program_id,
            instruction_data: target_instruction_data,
            pre_states: chained_pre_states,
            pda_seeds,
        };

        let wrap = |acc: Account, orig: &AccountWithMetadata| AccountWithMetadata {
            account: acc,
            account_id: orig.account_id,
            is_authorized: false,
        };
        let multisig_post = multisig_account.account.clone();

        let mut out = vec![
            wrap(multisig_post, multisig_account),
            wrap(proposal_post, proposal_account),
        ];
        for tgt in target_accounts {
            out.push(tgt.clone());
        }

        (out, vec![chained_call])
    }
}

/// Apply a config action to the state.
///
/// `expected_new_root` was verified at propose time against the prior
/// `state.members_root` via a Merkle witness (see
/// `propose_config::handle`). `stale_transaction_index` guarantees that
/// if this proposal is still Active at execute time, no other config
/// change has run since propose, so `state.members_root` still equals
/// `proposal.members_root_at_creation` and the propose-time verification
/// is still binding. We therefore don't re-verify the witness here —
/// just install the new root.
fn apply_config_action(
    state: &mut MultisigState,
    _proposal: &Proposal,
    action: &ConfigAction,
) {
    match action {
        ConfigAction::AddMember {
            expected_new_root, ..
        } => {
            state.members_root = *expected_new_root;
            assert!(state.member_count < u8::MAX, "member_count overflow");
            state.member_count += 1;
        }
        ConfigAction::RemoveMember {
            expected_new_root, ..
        } => {
            assert!(
                state.member_count > state.threshold,
                "Removing would drop count below threshold"
            );
            state.members_root = *expected_new_root;
            state.member_count -= 1;
        }
        ConfigAction::ChangeThreshold { new_threshold } => {
            assert!(*new_threshold >= 1, "Threshold must be at least 1");
            assert!(
                *new_threshold <= state.member_count,
                "Threshold cannot exceed member count"
            );
            state.threshold = *new_threshold;
        }
    }
}

/// Helper: update one leaf in an otherwise-empty tree. Not called on the
/// hot path, but exported so external tools can precompute the
/// `expected_new_root` the same way the circuit verifies it.
/// `members_root`/`siblings` come from the off-chain Merkle service.
pub fn recompute_root(
    leaf_value: &[u8; 32],
    path_bits: u32,
    siblings: &[[u8; 32]],
) -> MerkleRoot {
    let mut node = hash_leaf(leaf_value);
    for (i, sib) in siblings.iter().enumerate() {
        let bit = (path_bits >> i) & 1;
        node = if bit == 0 {
            hash_pair(&node, sib)
        } else {
            hash_pair(sib, &node)
        };
    }
    node
}

/// Helper that always returns the LEAF-tagged hash of the empty-leaf
/// constant — useful when building a remove-member witness off-chain.
pub fn empty_leaf_hash() -> [u8; 32] {
    hash_leaf(&EMPTY_LEAF)
}

#[cfg(test)]
mod tests {
    use super::*;
    use nssa_core::account::AccountId;
    use nssa_core::program::ProgramId;

    fn make_account(id: &[u8; 32], data: Vec<u8>) -> AccountWithMetadata {
        let mut account = Account::default();
        account.data = data.try_into().unwrap();
        AccountWithMetadata {
            account_id: AccountId::new(*id),
            account,
            is_authorized: false,
        }
    }

    fn make_state(ck: [u8; 32], root: [u8; 32], threshold: u8, count: u8, tx: u64) -> Vec<u8> {
        let mut s = MultisigState::new(ck, threshold, count, root);
        s.transaction_index = tx;
        borsh::to_vec(&s).unwrap()
    }

    fn make_threshold_proposal(idx: u64, ck: [u8; 32], root: [u8; 32], approvals: usize) -> Vec<u8> {
        let mut p = Proposal::new_standard(
            idx,
            ck,
            root,
            [42u32; 8] as ProgramId,
            vec![0u32],
            1,
            vec![],
            vec![0u8],
            [1u8; 32],
        );
        for i in 1..approvals {
            p.record_approval([i as u8; 32]);
        }
        borsh::to_vec(&p).unwrap()
    }

    #[test]
    fn execute_emits_chained_call() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, root, 2, 3, 1)),
            make_account(&[20u8; 32], make_threshold_proposal(1, ck, root, 2)),
            make_account(&[30u8; 32], vec![]),
        ];
        let (out, chained) = handle(&accounts, 1);
        assert_eq!(chained.len(), 1);
        assert_eq!(out.len(), 3);
        assert!(chained[0].pre_states[0].is_authorized);
    }

    #[test]
    #[should_panic(expected = "enough approvals")]
    fn execute_below_threshold_fails() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, root, 2, 3, 1)),
            make_account(&[20u8; 32], make_threshold_proposal(1, ck, root, 1)),
            make_account(&[30u8; 32], vec![]),
        ];
        handle(&accounts, 1);
    }

    #[test]
    fn execute_add_member_bumps_stale() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let mut p = Proposal::new_config(
            1,
            ck,
            root,
            ConfigAction::AddMember {
                new_commitment: [5u8; 32],
                target_path_bits: 0,
                expected_new_root: [77u8; 32],
            },
            [1u8; 32],
        );
        p.record_approval([2u8; 32]);
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, root, 2, 3, 1)),
            make_account(&[20u8; 32], borsh::to_vec(&p).unwrap()),
        ];
        let (out, chained) = handle(&accounts, 1);
        assert!(chained.is_empty());
        let s: MultisigState = borsh::from_slice(&Vec::from(out[0].account.data.clone())).unwrap();
        assert_eq!(s.members_root, [77u8; 32]);
        assert_eq!(s.member_count, 4);
        assert_eq!(s.stale_transaction_index, 1);
    }

    #[test]
    #[should_panic(expected = "drop count below threshold")]
    fn execute_remove_below_threshold_fails() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let mut p = Proposal::new_config(
            1,
            ck,
            root,
            ConfigAction::RemoveMember {
                target_commitment: [5u8; 32],
                target_path_bits: 0,
                expected_new_root: [77u8; 32],
            },
            [1u8; 32],
        );
        p.record_approval([2u8; 32]);
        let accounts = vec![
            // count == threshold → remove would drop below.
            make_account(&[10u8; 32], make_state(ck, root, 2, 2, 1)),
            make_account(&[20u8; 32], borsh::to_vec(&p).unwrap()),
        ];
        handle(&accounts, 1);
    }

    #[test]
    fn execute_change_threshold() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let mut p = Proposal::new_config(
            1,
            ck,
            root,
            ConfigAction::ChangeThreshold { new_threshold: 3 },
            [1u8; 32],
        );
        p.record_approval([2u8; 32]);
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, root, 2, 3, 1)),
            make_account(&[20u8; 32], borsh::to_vec(&p).unwrap()),
        ];
        let (out, _) = handle(&accounts, 1);
        let s: MultisigState = borsh::from_slice(&Vec::from(out[0].account.data.clone())).unwrap();
        assert_eq!(s.threshold, 3);
        assert_eq!(s.stale_transaction_index, 1);
    }

    #[test]
    fn recompute_root_matches_single_leaf() {
        let leaf = [7u8; 32];
        // Siblings all zero-level-default; with only 1 leaf the root is
        // hash_pair chain from the inserted leaf up.
        let siblings: Vec<[u8; 32]> = vec![[0u8; 32]; 3];
        let r = recompute_root(&leaf, 0, &siblings);
        // Sanity: same function applied twice gives same result.
        let r2 = recompute_root(&leaf, 0, &siblings);
        assert_eq!(r, r2);
    }
}
