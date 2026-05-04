//! BLS-based threshold encryption for the encrypted mempool, per
//! whitepaper section 3.6.
//!
//! Constructed on BLS12-381 (shared with [`crate::bls`]). Distributed
//! key generation and consensus integration are specified in whitepaper
//! sections 8 and 9 and implemented in their respective phases; this
//! module provides only the pure-cryptographic surface (encryption,
//! decryption-share generation, share combination).
