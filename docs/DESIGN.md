# Design notes — lez-private-multisig

## Goals

1. **Shielded voting.** An observer watching the chain should learn the
   vote count on each proposal, but not who voted.
2. **Hidden membership.** Member identities are not stored on-chain.
   Only a Merkle root commits to the set.
3. **ZK threshold proof.** The on-chain threshold check reduces to
   "`threshold`-many distinct, well-formed nullifiers exist in the
   approval set", with each nullifier backed by a succinct proof of
   membership in the committed set.
4. **Stay inside LEZ's native proof composition.** No new trusted
   setup, no off-chain aggregator — the outer LEZ proof simply consumes
   an inner Risc0 assumption.

## Trust boundaries

- **Member machine**: holds `secret`, `view_salt`, and a copy of the
  Merkle tree. Must not leak these. Generates receipts locally.
- **LEZ prover**: receives journal bytes (in the instruction) and the
  inner receipt (as a side-channel assumption). Aggregates everything
  into the outer LEZ proof.
- **Chain**: sees journal, nullifiers, and the outer proof. Verifies
  everything by checking the outer Risc0 proof.

No party in this chain needs to trust any other for *integrity*
(every claim is proof-backed). Members trust each other only to the
extent that the multisig's threshold contract requires — same as the
public version.

## Nullifier scoping

```
nullifier = SHA256(DOMAIN || "NULLIFIER" || secret || proposal_id || create_key)
```

Each field is there for a specific attack:

- `secret` — same secret always yields the same nullifier for the same
  scope. That's what makes double-voting detectable.
- `proposal_id = SHA256(DOMAIN || "PROPOSAL" || create_key || be(index))`
  — binds the nullifier to a specific proposal. Without this, a voter
  could replay one receipt across every proposal in the multisig.
- `create_key` — binds the nullifier to one multisig. Without this, a
  voter's nullifier for multisig A's proposal 1 would collide with
  multisig B's proposal 1 if both used index 1. Even with `proposal_id`
  already including `create_key`, we re-mix it in here as
  defence-in-depth against circuit bugs.

The guest re-derives `proposal_id` from `(create_key, proposal_index)`
inside the circuit so the public journal's `proposal_id` cannot be
forged — if we let the prover hand in `proposal_id` directly, a
malicious prover could produce a receipt with the right nullifier but
a lied-about scope.

### Why `vote_type` is NOT in the nullifier

`vote_type` is committed in the journal (so handlers can dispatch the
right action and a relayer cannot re-route an `Approve` receipt as a
`Reject` or vice versa), but it is **not** part of the nullifier
preimage.

An earlier draft of this design put `vote_type` in the preimage to let
a member rescind an approval and instead reject. The cost of that
flexibility is that the same secret produces distinct nullifiers
(Approve / Reject) on the same proposal, so a member could land one
nullifier in `approval_nullifiers` *and* one in `rejection_nullifiers`
simultaneously — voting in both buckets — and an earlier draft with
a third `Propose` variant let the proposer double-count alongside
their own subsequent `Approve`.

Scoping the nullifier only to `(secret, proposal, multisig)`, combined
with `nullifier_used` checking *both* buckets, gives strict
one-vote-per-member per proposal across propose/approve/reject. A
member who has already voted cannot flip; they can't double-count via
proposer auto-approval; they can't simultaneously approve and reject.
This matches how production multisigs (Squads, Safe) actually behave.

## Why `members_root_at_creation` is on each proposal

Two layered defences against removed-member stale votes:

1. **Proposal-level**: each `Proposal` records
   `members_root_at_creation`. Every vote proof for that proposal must
   verify against this exact root — not the current state root. So
   once a member is removed, their pre-existing commitment stops
   verifying under the new root, but the old root is still the
   reference for all *existing* proposals. Removed members could, in
   principle, still vote on old proposals — which is why we have the
   second layer.
2. **Multisig-level**: `stale_transaction_index` is bumped on every
   successful config-change execute. The Approve/Reject/Execute
   handlers refuse to touch any proposal with
   `index <= stale_transaction_index`. Config change → every pending
   proposal is retired in one operation. This is lifted directly from
   Squads v4 (`invalidate_prior_transactions`).

Neither layer is sufficient alone:

- Without (1), voters submitting the *current* root would succeed
  because we'd have no way to tell which root they're proving against.
- Without (2), the old-root check passes for any member still in the
  tree — but a member removed *after* the proposal was created could
  still vote, because the `members_root_at_creation` still contains
  their commitment.

The on-chain bump is cheap (a `u64` write) and the check is
O(1) — we're not iterating to invalidate proposals one by one.

## Witnessed root transitions for config changes

`AddMember` and `RemoveMember` are the only operations that move
`state.members_root`. Naively letting the proposer commit any
`expected_new_root` lets a malicious proposer install an arbitrary tree
on threshold approval — e.g. a tree where only they have a commitment.
The threshold check then runs on a degenerate member set.

To prevent that, every `AddMember` / `RemoveMember` proposal carries a
Merkle witness `(target_path_bits, siblings)` covering the leaf that
will change. `propose_config::handle` calls
`zk_common::verify_and_replace`:

- **AddMember**: asserts the slot at `target_path_bits` is currently
  `hash_leaf(EMPTY_LEAF)` under `state.members_root`, then computes the
  root that would result from swapping in `hash_leaf(new_commitment)`,
  and asserts it equals `expected_new_root`.
- **RemoveMember**: asserts the slot at `target_path_bits` is currently
  `hash_leaf(target_commitment)`, then computes the root with that slot
  replaced by `hash_leaf(EMPTY_LEAF)`, and asserts it equals
  `expected_new_root`.

A proposer whose `expected_new_root` doesn't agree with what the
witness produces is rejected at propose time. A proposer who can't
produce a valid witness (no `EMPTY_LEAF` at any slot they can name, or
no `target_commitment` to remove) can't open the proposal at all.

We don't re-verify at execute time. The reasoning: between propose and
execute, the only event that can move `state.members_root` is *another*
config change executing. If that happens, `stale_transaction_index`
bumps to the latest `transaction_index`, retiring this proposal — and
the `is_stale` check at execute will reject it. So if a proposal is
still Active at execute time, `state.members_root` is unchanged from
propose time, and the propose-time verification is still binding.

The witness itself is *not* stored on-chain (it's a 320-byte sibling
array per proposal). Only the result — `expected_new_root` and the
chosen `target_path_bits` — is stored, so an off-chain indexer can
inspect what was proposed.

## Domain separation

`DOMAIN_TAG = b"lez-private-multisig-v1"` is prepended to every
SHA-256 in `zk_common`:

- `hash_leaf`: `SHA256(b"LEAF" || commitment)`
- `hash_pair`: `SHA256(b"NODE" || left || right)`
- `commitment_from_secret`: `SHA256(DOMAIN || b"COMMIT" || secret || view_salt)`
- `proposal_id`: `SHA256(DOMAIN || b"PROPOSAL" || create_key || be(index))`
- `nullifier_from_secret`: `SHA256(DOMAIN || b"NULLIFIER" || secret || proposal_id || vote_type || create_key)`

LEAF / NODE tags prevent length-extension-style tree attacks (an
internal node is never accepted as a leaf pre-image, and vice versa).
Bumping `DOMAIN_TAG` on a circuit change cleanly invalidates prior
receipts.

## Why SHA-256 (not Poseidon)

Risc0's RV32 zkVM includes a SHA-256 accelerator. A Merkle-depth-10
proof is ~11 compressions for the path + 1 leaf + a few more for
commitment/nullifier/proposal_id derivation. This is dramatically
cheaper than a circuit-friendly hash implemented in RISC-V
instructions (no corresponding accelerator exists). The only cost of
SHA vs Poseidon is that the witness is 32-byte rather than
field-element sized, which doesn't matter here.

## Threat model summary

Attacker capability → outcome:

| Attack | Defense |
|---|---|
| Forge membership without holding a secret | Requires forging Risc0 receipt → infeasible |
| Replay a vote across proposals | `proposal_id` in nullifier |
| Replay a vote across multisigs | `create_key` in nullifier |
| Double-vote on same proposal (any combination of Approve / Reject) | One nullifier per `(secret, proposal, multisig)`; `nullifier_used` checks both buckets |
| Proposer double-counts via propose-then-approve | Propose mints an `Approve`-type nullifier; subsequent `Approve` from the same member collides |
| Member approves and also rejects | Same nullifier value would land in both buckets → second submission rejected |
| Removed member votes on existing proposal | `members_root_at_creation` freezes the set + `stale_transaction_index` |
| Submit with fake Merkle root | Root check in circuit + `==` check in handler |
| Malicious prover spoofs `proposal_id` | Guest re-derives `proposal_id` from witness, not from journal |
| Malicious prover spoofs `members_root` | Guest emits the actual root it verified against |
| Malicious proposer installs an arbitrary `expected_new_root` on AddMember / RemoveMember | Witnessed root transition: `propose_config` recomputes the new root from a Merkle path and asserts it equals `expected_new_root` |
| Relayer re-routes an Approve receipt as a Reject | `vote_type` is committed in the journal; handler asserts it matches the instruction |
| Denial of service via spamming `Propose` | Propose requires a valid membership proof; non-members cannot spam |
| Executor censors a ready proposal | Execute is permissionless — any relayer can submit |

## Known limitations

- **Member removal doesn't clear the spot**: `IncrementalMerkleTree::remove`
  writes `EMPTY_LEAF` into the slot without compacting. A tree with
  many removals has "holes" but is still correct — the slot is just
  unusable for append. Capacity is 1024 with the current `MERKLE_DEPTH`.
- **No cancel**: the public version's `reject` sets the proposal to
  `Rejected` once enough rejections accumulate; we preserve that.
  There's no explicit cancel by the proposer (who is anonymous anyway).
- **Receipt size**: the inner receipt is not carried on-chain; only
  the journal is. This relies on the LEZ prover accepting an
  out-of-band assumption. If that doesn't match the deployed LEZ API,
  swap `MembershipJournal` for a full receipt blob and add a
  deserialize+verify in `verify.rs`.
