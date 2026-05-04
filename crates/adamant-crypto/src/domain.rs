//! Centralised domain-separation registry.
//!
//! Per whitepaper section 3.3.1, every cryptographic operation requiring
//! domain separation MUST reference a tag from this file. The general
//! format for protocol-internal hash inputs is `b"ADAMANT-v1-<context>"`.
//! BLS hash-to-curve uses the IRTF-standard ciphersuite-tag format.
//!
//! # Adding a tag
//!
//! 1. Add a `pub const` here, with a doc comment naming the whitepaper
//!    section that requires it.
//! 2. Reference the constant from the using module — never inline a tag
//!    string at a use site.
//! 3. Call out the addition in the commit message; this file is part of
//!    the security audit surface.
//!
//! # Removing or renaming
//!
//! Domain tags are part of the protocol's consensus rules. Removing or
//! renaming a tag is a breaking change to the chain and requires the
//! same treatment as any other consensus rule change (whitepaper 3.10).
//!
//! # Status of tags
//!
//! Whitepaper v0.1 explicitly names exactly one complete domain tag, for
//! BLS hash-to-curve (section 3.4.3). Other sections reference a
//! `domain_tag` placeholder for protocol contexts whose exact byte string
//! is to be specified when those sections are implemented:
//!
//! | Context | Whitepaper section | Status |
//! |---------|--------------------|--------|
//! | Account address derivation | 4 | Tag string deferred to Phase 3 (`adamant-account`). |
//! | `ObjectId` derivation | 5 | Tag string deferred to Phase 4 (`adamant-state`). |
//! | Nullifier (Poseidon, in-circuit) | 7 | Tag string deferred to Phase 6 (`adamant-privacy`). |
//! | Stealth-address shared secret | 7 | Tag string deferred to Phase 6 (`adamant-privacy`). |
//! | Memo key derivation | 7 | Tag string deferred to Phase 6 (`adamant-privacy`). |
//!
//! Each deferred tag will land here, with its whitepaper section cited,
//! when the corresponding subsystem is implemented.

/// BLS signature hash-to-curve domain tag, per whitepaper section 3.4.3.
///
/// This is the IRTF `draft-irtf-cfrg-hash-to-curve` ciphersuite tag for
/// suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`, with the protocol-specific
/// suffix `ADAMANT_v1`. Used as the DST for all BLS aggregate signatures
/// over G1.
pub const BLS_SIG_HASH_TO_CURVE: &[u8] = b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1";
