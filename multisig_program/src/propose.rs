//! Propose — opens a new ChainedCall proposal, authenticated by a
//! membership ZK proof with `vote_type = Approve` (propose counts as
//! the proposer's first approval; see `zk_common::VoteType`).
//!
//! Accounts:
//! - accounts[0]: multisig_state PDA (mut, bumps transaction_index)
//! - accounts[1]: proposal PDA (init, uninitialized)
//!
//! The proposer is NOT passed as an account. Their identity is hidden
//! inside the membership receipt; only the nullifier leaks.

use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::{ChainedCall, InstructionData, ProgramId};
use multisig_core::{MembershipJournal, MultisigState, Proposal};
use zk_common::{proposal_id as derive_proposal_id, VoteType};

use crate::verify::verify_and_decode;

#[allow(clippy::too_many_arguments)]
pub fn handle(
    accounts: &[AccountWithMetadata],
    target_program_id: &ProgramId,
    target_instruction_data: &InstructionData,
    target_account_count: u8,
    pda_seeds: &[[u8; 32]],
    authorized_indices: &[u8],
    proposal_index_arg: u64,
    membership_journal: &MembershipJournal,
) -> (Vec<Account>, Vec<ChainedCall>) {
    assert!(
        accounts.len() >= 2,
        "Propose requires multisig_state + proposal accounts"
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

    let next_index = state.next_proposal_index();
    assert_eq!(
        next_index, proposal_index_arg,
        "proposal_index arg does not match next transaction_index"
    );

    // Verify the ZK membership proof + decode its journal.
    let journal = verify_and_decode(membership_journal);

    assert_eq!(
        journal.multisig_create_key, state.create_key,
        "Proof is not scoped to this multisig"
    );
    assert_eq!(
        journal.members_root, state.members_root,
        "Proof was generated against a different member set"
    );
    let expected_pid = derive_proposal_id(&state.create_key, next_index);
    assert_eq!(
        journal.proposal_id, expected_pid,
        "Proof proposal_id does not match this proposal"
    );
    // The proposer's receipt is minted as an `Approve` (propose counts
    // as their one approval). See `zk_common::VoteType` for why the
    // nullifier no longer depends on vote_type.
    assert_eq!(
        journal.vote_type,
        VoteType::Approve,
        "Proof vote_type must be Approve (propose counts as the proposer's first approval)"
    );

    let proposal = Proposal::new_standard(
        next_index,
        state.create_key,
        state.members_root,
        target_program_id.clone(),
        target_instruction_data.clone(),
        target_account_count,
        pda_seeds.to_vec(),
        authorized_indices.to_vec(),
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

    fn make_state(create_key: [u8; 32], threshold: u8, count: u8, root: [u8; 32]) -> Vec<u8> {
        borsh::to_vec(&MultisigState::new(create_key, threshold, count, root)).unwrap()
    }

    fn journal_bytes(
        create_key: [u8; 32],
        root: [u8; 32],
        proposal_index: u64,
        vote_type: VoteType,
        nullifier: [u8; 32],
    ) -> Vec<u8> {
        let pid = derive_proposal_id(&create_key, proposal_index);
        let j = ProofJournal {
            members_root: root,
            multisig_create_key: create_key,
            proposal_id: pid,
            vote_type,
            nullifier,
        };
        borsh::to_vec(&j).unwrap()
    }

    #[test]
    fn propose_increments_index_and_records_nullifier() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, 2, 3, root)),
            make_account(&[20u8; 32], vec![]),
        ];
        let journal = journal_bytes(ck, root, 1, VoteType::Approve, [9u8; 32]);
        let program_id: ProgramId = [42u32; 8];

        let (out, chained) = handle(
            &accounts,
            &program_id,
            &vec![0u32],
            1,
            &[],
            &[],
            1,
            &journal,
        );
        assert!(chained.is_empty());
        let state: MultisigState = borsh::from_slice(&Vec::from(out[0].data.clone())).unwrap();
        assert_eq!(state.transaction_index, 1);
        let prop: Proposal = borsh::from_slice(&Vec::from(out[1].data.clone())).unwrap();
        assert_eq!(prop.index, 1);
        assert_eq!(prop.approval_nullifiers, vec![[9u8; 32]]);
        assert_eq!(prop.members_root_at_creation, root);
    }

    #[test]
    #[should_panic(expected = "different member set")]
    fn wrong_root_rejected() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, 2, 3, root)),
            make_account(&[20u8; 32], vec![]),
        ];
        let journal = journal_bytes(ck, [99u8; 32], 1, VoteType::Approve, [9u8; 32]);
        let program_id: ProgramId = [42u32; 8];
        handle(&accounts, &program_id, &vec![0u32], 1, &[], &[], 1, &journal);
    }

    #[test]
    #[should_panic(expected = "vote_type must be Approve")]
    fn wrong_vote_type_rejected() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, 2, 3, root)),
            make_account(&[20u8; 32], vec![]),
        ];
        let journal = journal_bytes(ck, root, 1, VoteType::Reject, [9u8; 32]);
        let program_id: ProgramId = [42u32; 8];
        handle(&accounts, &program_id, &vec![0u32], 1, &[], &[], 1, &journal);
    }

    #[test]
    #[should_panic(expected = "does not match next transaction_index")]
    fn index_mismatch_rejected() {
        let ck = [1u8; 32];
        let root = [2u8; 32];
        let accounts = vec![
            make_account(&[10u8; 32], make_state(ck, 2, 3, root)),
            make_account(&[20u8; 32], vec![]),
        ];
        let journal = journal_bytes(ck, root, 5, VoteType::Approve, [9u8; 32]);
        let program_id: ProgramId = [42u32; 8];
        handle(&accounts, &program_id, &vec![0u32], 1, &[], &[], 5, &journal);
    }
}
