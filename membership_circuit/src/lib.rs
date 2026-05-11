//! Membership circuit crate.
//!
//! The guest (in `guest/`) is compiled by risc0-build at `build.rs` time.
//! This crate re-exports the generated constants unconditionally so the
//! multisig program (which may be compiled for the Risc0 guest target
//! without `std`) can reference `MEMBERSHIP_PROOF_ID` from inside an
//! `env::verify(...)` call.
//!
//! The host-only machinery — the incremental Merkle tree and the
//! `ProofBuilder` that actually drives the prover — is gated on the `std`
//! feature (default on). Turning `std` off gives a no_std-friendly crate
//! that just exposes `MEMBERSHIP_PROOF_ID` / `MEMBERSHIP_PROOF_ELF`.

#![cfg_attr(not(feature = "std"), no_std)]

// The risc0-build invocation in `build.rs` emits `methods.rs` under OUT_DIR
// with `MEMBERSHIP_PROOF_ELF` and `MEMBERSHIP_PROOF_ID` constants. These are
// plain consts (`&[u8]` and `[u32; 8]`), so they compile in no_std.
include!(concat!(env!("OUT_DIR"), "/methods.rs"));

#[cfg(feature = "std")]
mod host;

#[cfg(feature = "std")]
pub use host::*;
