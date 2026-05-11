# lez-private-multisig

A shielded-voting M-of-N multisig for Logos Execution Zone (LEZ).

This is a privacy-preserving variant of [lez-multisig](../lez-multisig).
Members never appear on-chain by name. Votes never reveal who voted.
Threshold is enforced by counting anonymous nullifiers.

## What changes vs. the public version

| | lez-multisig | lez-private-multisig |
|---|---|---|
| Members on-chain | `Vec<[u8;32]>` (public keys) | `MerkleRoot` (commitment tree) |
| Vote authentication | LEZ signer check on named member | Risc0 ZK membership proof |
| Vote storage | `approved: Vec<[u8;32]>` (public keys) | `approval_nullifiers: Vec<[u8;32]>` (anonymous tags) |
| Proposer identity | On-chain | Hidden (only a `Propose`-scoped nullifier is visible) |
| Executor identity | Must be a member | Permissionless |
| Stale-vote handling | None (audit finding H2) | `stale_transaction_index` bumps on every config change |

## Repo layout

```
zk_common/             — shared types + SHA-256 helpers, no_std, used by
                         the guest, the host, and the program
membership_circuit/    — Risc0 circuit proving (commitment in Merkle
                         tree, correctly-derived nullifier for a scope)
  guest/                 inner guest, runs on the prover's machine
  src/host.rs            IncrementalMerkleTree + ProofBuilder (std only)
multisig_core/         — instruction enum + on-chain state types, no
                         cryptographic primitives besides what zk_common
                         exports
multisig_program/      — the SPEL/LEZ program itself
  src/verify.rs          single call site for env::verify(MEMBERSHIP_PROOF_ID)
  src/{create_multisig,propose,propose_config,approve,reject,execute}.rs
methods/               — outer LEZ guest build (Risc0 wrapper around
                         multisig_program::main)
```

## How a vote flows

1. **Off-chain**: a member uses `ProofBuilder::build(proposal_index,
   VoteType::Approve)` (for propose or approve) or
   `VoteType::Reject` (for reject) to produce a Risc0 receipt. Its
   journal commits to `(members_root, multisig_create_key, proposal_id,
   vote_type, nullifier)` — note `vote_type` is committed in the
   journal (so a relayer can't re-route an Approve receipt as a
   Reject) but is *not* in the nullifier preimage, so any second vote
   from the same member on the same proposal collides regardless of
   which bucket it targets. The witness (`secret`, `view_salt`,
   `path_bits`, `siblings`) stays on the member's machine.
2. **Submit**: the member (or any relayer) sends the `Approve`
   instruction carrying the journal bytes. The receipt is handed to
   the LEZ prover out-of-band as a Risc0 *assumption*.
3. **Inside the outer LEZ guest**:
   - `verify_and_decode` calls
     `env::verify(MEMBERSHIP_PROOF_ID, journal_bytes)`, which consumes
     the assumption. If no matching receipt was supplied, the outer
     guest halts and no proof is ever produced.
   - The handler checks the decoded `ProofJournal` against the current
     `MultisigState` and the target `Proposal` (scope, root, vote
     type), then appends the nullifier.
4. **Execute**: permissionless. Once
   `proposal.approval_nullifiers.len() >= state.threshold`, anyone can
   submit an `Execute`, which emits the declared `ChainedCall`.

## What privacy is (and isn't) provided

Provided:
- The set of members (beyond their count) is hidden from any observer
  that isn't already part of the member set.
- For a given proposal, observers cannot link a vote back to a member
  identity or correlate votes across proposals by the same member.

Not provided:
- Transaction-graph privacy (the relayer and the broadcaster see the
  submission source).
- Proposal payload privacy (the `ChainedCall` arguments are public;
  what's hidden is *who authorised it*).
- Nullifier-to-nullifier unlinkability across the full history: if the
  same `view_salt` is reused, two nullifiers from the same member for
  different proposals are independent, but an adversary that
  compromises a member's secret can retroactively identify every vote
  they ever cast.

## Build

The project is structured as a Cargo workspace, same conventions as
lez-multisig:

```
cargo build -p multisig_core
cargo test  -p multisig_core
cargo test  -p zk_common
cargo test  -p membership_circuit   # host tests (tree + proof roundtrip)
cargo build -p private-multisig-methods   # builds the outer guest ELF
```

Generating a real receipt requires the Risc0 toolchain; end-to-end
tests that drive `ProofBuilder` are slow and are marked `#[ignore]`
unless you opt in.

## Security notes

See [DESIGN.md](DESIGN.md) for the threat model, domain-separation
choices, and why `members_root_at_creation` + `stale_transaction_index`
together close the removed-member-voting hole found in the audit of the
public version.

## Status

Reference implementation for the LP-0002 prize spec. Not audited. Do
not use with live funds.
