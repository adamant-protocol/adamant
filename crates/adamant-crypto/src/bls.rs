//! BLS12-381 signature and pairing wrappers, per whitepaper section 3.4.3.
//!
//! Aggregate signatures for validator vote aggregation. Signatures are
//! over G1 (48 bytes); public keys are over G2 (96 bytes). Hash-to-curve
//! uses the domain tag [`crate::domain::BLS_SIG_HASH_TO_CURVE`].
