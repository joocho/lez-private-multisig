//! CreateMultisig — initializes a new M-of-N private multisig.
//!
//! Delta vs. public lez-multisig: no member accounts are passed in, none
//! are claimed, no identities are written on-chain. The creator simply
//! publishes the Merkle root over member commitments and a member count.
//! Member privacy is an emergent property of the root being opaque.

use nssa_core::account::{Account, AccountWithMetadata};
use nssa_core::program::ChainedCall;
use multisig_core::MultisigState;
use zk_common::MerkleRoot;

/// Expected accounts:
/// - accounts[0]: multisig_state (PDA, uninitialized) — derived from create_key.
///
/// Authorization: anyone can create a multisig. The PDA derivation binds
/// the state to a unique create_key, so collisions self-resolve.
pub fn handle(
    accounts: &[AccountWithMetadata],
    create_key: &[u8; 32],
    threshold: u8,
    member_count: u8,
    members_root: &MerkleRoot,
) -> (Vec<Account>, Vec<ChainedCall>) {
    assert!(threshold >= 1, "Threshold must be at least 1");
    assert!(member_count >= 1, "Multisig must have at least one member");
    assert!(threshold <= member_count, "Threshold cannot exceed member count");

    assert!(!accounts.is_empty(), "CreateMultisig requires a state account");
    assert!(
        accounts[0].account == Account::default(),
        "Multisig state account must be uninitialized"
    );

    let state = MultisigState::new(*create_key, threshold, member_count, *members_root);
    let state_bytes = borsh::to_vec(&state).unwrap();
    let mut multisig_account = Account::default();
    multisig_account.data = state_bytes.try_into().unwrap();

    (vec![multisig_account], vec![])
}

#[cfg(test)]
mod tests {
    use super::*;
    use nssa_core::account::AccountId;

    fn uninitialized(id: &[u8; 32]) -> AccountWithMetadata {
        AccountWithMetadata {
            account_id: AccountId::new(*id),
            account: Account::default(),
            is_authorized: false,
        }
    }

    #[test]
    fn creates_state_with_published_root() {
        let accounts = vec![uninitialized(&[9u8; 32])];
        let root = [42u8; 32];
        let (out, chained) = handle(&accounts, &[1u8; 32], 2, 3, &root);
        assert!(chained.is_empty());
        let state: MultisigState =
            borsh::from_slice(&Vec::from(out[0].data.clone())).unwrap();
        assert_eq!(state.threshold, 2);
        assert_eq!(state.member_count, 3);
        assert_eq!(state.members_root, root);
        assert_eq!(state.transaction_index, 0);
        assert_eq!(state.stale_transaction_index, 0);
    }

    #[test]
    #[should_panic(expected = "at least 1")]
    fn zero_threshold_rejected() {
        let accounts = vec![uninitialized(&[9u8; 32])];
        handle(&accounts, &[0u8; 32], 0, 3, &[0u8; 32]);
    }

    #[test]
    #[should_panic(expected = "exceed member count")]
    fn threshold_over_count_rejected() {
        let accounts = vec![uninitialized(&[9u8; 32])];
        handle(&accounts, &[0u8; 32], 5, 3, &[0u8; 32]);
    }

    #[test]
    #[should_panic(expected = "must be uninitialized")]
    fn already_initialized_rejected() {
        let mut a = Account::default();
        a.data = vec![1u8, 2, 3].try_into().unwrap();
        let accounts = vec![AccountWithMetadata {
            account_id: AccountId::new([9u8; 32]),
            account: a,
            is_authorized: false,
        }];
        handle(&accounts, &[0u8; 32], 1, 1, &[0u8; 32]);
    }
}
