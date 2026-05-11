//! Approve — records an approval nullifier on an active proposal,
//! authenticated by a membership ZK proof with `vote_type = Approve`.
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA (read-only here, but returned so the
//!   outer guest can match pre/post state counts)
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
        "Approve requires multisig_state + proposal accounts"
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

    assert_eq!(
        journal.multisig_create_key, state.create_key,
        "Proof is not scoped to this multisig"
    );
    // Critical: vote proofs are anchored to the *creation-time* root, not
    // the current one. After a config change the current root moves but
    // `stale_transaction_index` has already invalidated all prior proposals,
    // so this equality check is the second line of defence.
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
        VoteType::Approve,
        "Proof vote_type must be Approve"
    );

    assert!(
        !proposal.nullifier_used(&journal.nullifier),
        "Nullifier already used on this proposal"
    );
    proposal.record_approval(journal.nullifier);

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

    fn make_state(ck: [u8; 32], root: [u8; 32]) -> Vec<u8> {
        let mut s = MultisigState::new(ck, 2, 3, root);
        s.transaction_index = 1;
        borsh::to_vec(&s).unwrap()
    }

    fn make_proposal(index: u64, ck: [u8; 32], root: [u8; 32], seed_nullifier: [u8; 32]) -> Vec<u8> {
        let p = Proposal::new_standard(
            index,
            ck,
            root,
            [42u32; 8] as ProgramId,
            vec![0u32],
            1,
            vec![],
            vec![],
            seed_nullifier,
        );
        borsh::to_vec(&p).unwrap()
    }

    fn journal_bytes(
        ck: [u8; 32],
        root: [u8; 32],
        idx: u64,
        vt: VoteType,
        null: [u8; 32],
    ) -> Vec<u8> {
        let j = ProofJournal {
            members_root: root,
            multisig_create_key: ck,
            proposal_id: derive_proposal_id(&ck, idx),
            vote_type: vt,
            nullifier: null,
        };
        borsh::to_vec(&j).unwrap()
    }

    #[test]
    fn approve_records_nullifier() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, root)),
            make_account(&[20u8; 32], make_proposal(1, ck, root, [9u8; 32])),
        ];
        let j = journal_bytes(ck, root, 1, VoteType::Approve, [8u8; 32]);
        let (out, _) = handle(&accounts, 1, &j);
        let p: Proposal = borsh::from_slice(&Vec::from(out[1].data.clone())).unwrap();
        assert_eq!(p.approval_nullifiers, vec![[9u8; 32], [8u8; 32]]);
    }

    #[test]
    #[should_panic(expected = "already used")]
    fn duplicate_nullifier_rejected() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, root)),
            make_account(&[20u8; 32], make_proposal(1, ck, root, [9u8; 32])),
        ];
        // Same nullifier as the propose-nullifier already in the proposal.
        let j = journal_bytes(ck, root, 1, VoteType::Approve, [9u8; 32]);
        handle(&accounts, 1, &j);
    }

    #[test]
    #[should_panic(expected = "different member set")]
    fn root_drift_rejected() {
        let ck = [1u8; 32];
        let old_root = [2u8; 32];
        // State has moved to a new root (config change happened).
        let mut live = MultisigState::new(ck, 2, 3, [33u8; 32]);
        live.transaction_index = 2;
        live.stale_transaction_index = 0;
        let accounts = vec![
            make_account(&[10u8; 32], borsh::to_vec(&live).unwrap()),
            make_account(&[20u8; 32], make_proposal(1, ck, old_root, [9u8; 32])),
        ];
        // Attacker proves against the current root, not the creation root.
        let j = journal_bytes(ck, [33u8; 32], 1, VoteType::Approve, [8u8; 32]);
        handle(&accounts, 1, &j);
    }

    #[test]
    #[should_panic(expected = "invalidated by a config change")]
    fn stale_proposal_rejected() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let mut live = MultisigState::new(ck, 2, 3, root);
        live.transaction_index = 5;
        live.stale_transaction_index = 3;
        let accounts = vec![
            make_account(&[10u8; 32], borsh::to_vec(&live).unwrap()),
            make_account(&[20u8; 32], make_proposal(2, ck, root, [9u8; 32])),
        ];
        let j = journal_bytes(ck, root, 2, VoteType::Approve, [8u8; 32]);
        handle(&accounts, 2, &j);
    }
}
