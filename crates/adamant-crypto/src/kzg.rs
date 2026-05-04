//! KZG vector and polynomial commitments on BLS12-381, per whitepaper
//! section 3.7.2.
//!
//! Trusted-setup parameters are sourced from the Ethereum Powers of Tau
//! ceremony output; the specific reference is pinned in whitepaper
//! section 11 (Genesis & Constitution). This is the only point in the
//! protocol that depends on a trusted setup, and the dependency is
//! narrowly scoped to fixed-size validator-set vectors.
