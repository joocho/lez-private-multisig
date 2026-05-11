//! Reject — records a rejection nullifier on an active proposal.
//! Mirrors `approve.rs` except for vote_type and the dead-proposal check.
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA
//! - accounts[1]: proposal PDA (mut)

use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::ChainedCall;
use multisig_core::{MembershipJournal, MultisigState, Proposal, ProposalStatus};
use zk_common::{proposal_id as derive_proposal_id, VoteType};

use crate::verify::verify_and_decode;

pub fn handle(
    accounts: &[AccountWithMetadata],
    proposal_index: u64,
    membership_journal: &MembershipJournal,
) -> (Vec<Account>, Vec<ChainedCall>) {
    assert!(
        accounts.len() >= 2,
        "Reject requires multisig_state + proposal accounts"
    );
    let multisig_account = &accounts[0];
    let proposal_account = &accounts[1];

    let state_data: Vec<u8> = multisig_account.account.data.clone().into();
    let state: MultisigState =
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

    let journal = verify_and_decode(membership_journal);

    assert_eq!(journal.multisig_create_key, state.create_key);
    assert_eq!(
        journal.members_root, proposal.members_root_at_creation,
        "Proof was generated against a different member set"
    );
    let expected_pid = derive_proposal_id(&state.create_key, proposal_index);
    assert_eq!(
        journal.proposal_id, expected_pid,
        "Proof proposal_id does not match this proposal"
    );
    assert_eq!(
        journal.vote_type,
        VoteType::Reject,
        "Proof vote_type must be Reject"
    );

    assert!(
        !proposal.nullifier_used(&journal.nullifier),
        "Nullifier already used on this proposal"
    );
    proposal.record_rejection(journal.nullifier);

    if proposal.is_dead(state.threshold, state.member_count) {
        proposal.status = ProposalStatus::Rejected;
    }

    let proposal_bytes = borsh::to_vec(&proposal).unwrap();
    let mut proposal_post = proposal_account.account.clone();
    proposal_post.data = proposal_bytes.try_into().unwrap();

    let multisig_post = multisig_account.account.clone();
    (vec![multisig_post, proposal_post], vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use nssa_core::account::AccountId;
    use nssa_core::program::ProgramId;
    use zk_common::ProofJournal;

    fn make_account(id: &[u8; 32], data: Vec<u8>) -> AccountWithMetadata {
        let mut account = Account::default();
        account.data = data.try_into().unwrap();
        AccountWithMetadata {
            account_id: AccountId::new(*id),
            account,
            is_authorized: false,
        }
    }

    fn make_state(ck: [u8; 32], root: [u8; 32], threshold: u8, count: u8) -> Vec<u8> {
        let mut s = MultisigState::new(ck, threshold, count, root);
        s.transaction_index = 1;
        borsh::to_vec(&s).unwrap()
    }

    fn make_proposal(idx: u64, ck: [u8; 32], root: [u8; 32], seed: [u8; 32]) -> Vec<u8> {
        let p = Proposal::new_standard(
            idx,
            ck,
            root,
            [42u32; 8] as ProgramId,
            vec![0u32],
            1,
            vec![],
            vec![],
            seed,
        );
        borsh::to_vec(&p).unwrap()
    }

    fn journal_bytes(ck: [u8; 32], root: [u8; 32], idx: u64, null: [u8; 32]) -> Vec<u8> {
        let j = ProofJournal {
            members_root: root,
            multisig_create_key: ck,
            proposal_id: derive_proposal_id(&ck, idx),
            vote_type: VoteType::Reject,
            nullifier: null,
        };
        borsh::to_vec(&j).unwrap()
    }

    #[test]
    fn reject_records_nullifier() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, root, 2, 3)),
            make_account(&[20u8; 32], make_proposal(1, ck, root, [9u8; 32])),
        ];
        let j = journal_bytes(ck, root, 1, [8u8; 32]);
        let (out, _) = handle(&accounts, 1, &j);
        let p: Proposal = borsh::from_slice(&Vec::from(out[1].data.clone())).unwrap();
        assert_eq!(p.rejection_nullifiers, vec![[8u8; 32]]);
        assert_eq!(p.status, ProposalStatus::Active);
    }

    #[test]
    fn threshold_unreachable_marks_rejected() {
        // 2-of-2: any rejection kills the proposal.
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, root, 2, 2)),
            make_account(&[20u8; 32], make_proposal(1, ck, root, [9u8; 32])),
        ];
        let j = journal_bytes(ck, root, 1, [8u8; 32]);
        let (out, _) = handle(&accounts, 1, &j);
        let p: Proposal = borsh::from_slice(&Vec::from(out[1].data.clone())).unwrap();
        assert_eq!(p.status, ProposalStatus::Rejected);
    }
}
