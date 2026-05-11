//! ZK membership-proof verification helper.
//!
//! This is the single place where every handler ties back to the Risc0
//! assumption. Splitting it out keeps the handler code identity-opaque:
//! handlers never see secrets, commitments, or Merkle paths — only the
//! `ProofJournal` that the guest committed, after verification has been
//! consumed from the outer-guest assumption list.
//!
//! On `target_os = "zkvm"` (i.e. compiled into the outer LEZ guest),
//! `env::verify(MEMBERSHIP_PROOF_ID, journal_bytes)` is invoked — the
//! Risc0 runtime matches this against an added assumption and will halt
//! the outer guest if no matching inner receipt was supplied.
//!
//! On non-zkvm targets (host tests, IDL generation), the journal is
//! decoded without verification — tests drive handlers with hand-crafted
//! journals to exercise state-transition logic.

use multisig_core::MembershipJournal;
use zk_common::ProofJournal;

#[cfg(target_os = "zkvm")]
use risc0_zkvm::guest::env;

#[cfg(target_os = "zkvm")]
use membership_circuit::MEMBERSHIP_PROOF_ID;

/// Decode the journal bytes carried in the instruction, and (on the zkvm
/// target) consume the corresponding Risc0 assumption. Panics if either
/// step fails, which aborts the outer guest and invalidates the proof.
pub fn verify_and_decode(journal_bytes: &MembershipJournal) -> ProofJournal {
    #[cfg(target_os = "zkvm")]
    env::verify(MEMBERSHIP_PROOF_ID, journal_bytes.as_slice())
        .expect("membership receipt assumption missing or invalid");

    ProofJournal::from_bytes(journal_bytes).expect("malformed membership journal")
}
