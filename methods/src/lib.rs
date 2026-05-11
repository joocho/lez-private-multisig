// Hosts the risc0 build infrastructure that compiles `guest/src/bin/multisig.rs`
// into an ELF + image ID and embeds them as `PRIVATE_MULTISIG_ELF` /
// `PRIVATE_MULTISIG_ID` constants.
include!(concat!(env!("OUT_DIR"), "/methods.rs"));
