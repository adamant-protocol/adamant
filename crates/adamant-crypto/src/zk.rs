//! Halo 2 zk-SNARK proving and verification surface, per whitepaper
//! section 3.7.1.
//!
//! The full Halo 2 surface (circuits for shielded execution, recursive
//! verification) lands in Phase 6 (`adamant-privacy`). This module's
//! Phase 1 surface is limited to the Poseidon primitive shared with
//! [`crate::hash`]; the choice of Halo 2 crates beyond `halo2_gadgets`
//! is deferred to the start of Phase 6.
