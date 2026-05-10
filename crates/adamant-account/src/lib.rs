//! Account-level operations for the Adamant protocol.
//!
//! Phase 3 of the implementation lands a single protocol-level
//! deliverable from whitepaper section 4: the address-derivation
//! formula in section 4.2. Everything else in section 4 — validation
//! logic (section 4.3), view-key derivation (section 4.4, deferred to
//! the privacy layer in section 7), key rotation (section 4.5,
//! requires the VM and transaction format from section 6), recovery
//! patterns (section 4.6, smart-contract-level), and stealth-address
//! constructions (section 4.7, deferred to section 7) — defers to
//! later phases that supply the necessary substrate.
//!
//! # The address-derivation formula
//!
//! Per whitepaper section 4.2:
//!
//! `Address = SHA3-256(domain_tag || creation_tx_hash || creator_address || index)`
//!
//! Operationalised in this crate by composing three pieces of the
//! protocol's already-established discipline:
//!
//! 1. **The BIP-340 tagged-hash construction** (whitepaper section
//!    3.3.1, [`adamant_crypto::hash::sha3_256_tagged`]) supplies the
//!    `domain_tag || domain_tag || ...` prefix structure, where the
//!    repeated 32-byte SHA3-256 hash of the tag string serves as the
//!    domain-separation prefix. Naive `tag || input` concatenation
//!    admits prefix collisions for variable-length tags; BIP-340
//!    eliminates those.
//! 2. **A registered domain tag**
//!    ([`adamant_crypto::domain::ACCOUNT_ADDRESS`], the byte string
//!    `b"ADAMANT-v1-account-address"`) makes account addresses
//!    cryptographically distinct from every other protocol-level hash
//!    using the same primitive. Adding, renaming, or removing a tag
//!    is a consensus rule change (whitepaper 3.3.1).
//! 3. **BCS canonical serialisation** (whitepaper section 5.1.8) of
//!    the input tuple `(creation_tx_hash, creator_address, index)`
//!    produces a byte-identical input across every conforming
//!    implementation. Without canonical serialisation, two clients
//!    encoding the same logical inputs differently would derive
//!    different addresses and break consensus.
//!
//! Concretely:
//!
//! `Address = sha3_256_tagged(ACCOUNT_ADDRESS, BCS(DerivationInput))`
//!
//! where [`DerivationInput`] is the struct below; its BCS encoding is
//! exactly 72 bytes (32 bytes [`TxHash`] + 32 bytes [`Address`] + 8
//! bytes `u64` little-endian).
//!
//! # Why this is consensus-critical
//!
//! An account's address is the protocol-wide identifier under which
//! its objects are owned, its transactions are signed, and its state
//! is mutated. Two implementations that derive different addresses
//! from the same `(creation_tx_hash, creator_address, index)` would
//! disagree on which account a transaction targets — breaking
//! consensus on the very first account-creation transaction. The
//! known-answer regression test in this module's test suite pins the
//! wire format permanently: a future change that produces a
//! different address from the same input fails the KAT, signalling
//! the consensus-rule change explicitly.
//!
//! # Phase 4 reference
//!
//! `adamant-state` (Phase 4) implements the analogous `ObjectId`
//! derivation specified in whitepaper section 5.1.1:
//!
//! `ObjectId = SHA3-256(domain_tag || creation_tx_hash || creator_address || creation_index)`
//!
//! That formula has the same shape as section 4.2's, with a different
//! domain tag and the same input tuple shape. The implementation
//! pattern in this crate — registered tag, BCS-encoded input struct,
//! tagged-hash composition, KAT regression vector — is intended as
//! the reference for that next derivation. Phase 4 should mirror this
//! file's shape closely; the inline commentary here is heavier than
//! strictly necessary so Phase 4 has a worked example to mimic.

#![forbid(unsafe_code)]

use adamant_crypto::{domain, hash::sha3_256_tagged};
use adamant_types::{Address, TxHash};
use serde::Serialize;

/// Canonical input to the address-derivation formula
/// (whitepaper section 4.2).
///
/// Serialised via BCS (whitepaper section 5.1.8) to produce the
/// byte string fed into the tagged-hash construction. **Field order
/// is consensus-critical**: BCS encodes struct fields in
/// source-declaration order, and the order chosen here matches the
/// concatenation order specified in the whitepaper formula
/// `creation_tx_hash || creator_address || index`. Reordering fields
/// is a consensus rule change, not a refactor; the BCS-canonicality
/// test below pins the byte layout.
///
/// Encoded length is exactly 72 bytes:
///   - 32 bytes `creation_tx_hash` (fixed-size byte array, no length prefix)
///   - 32 bytes `creator_address` (fixed-size byte array, no length prefix)
///   - 8 bytes `index` (`u64` little-endian)
///
/// Private struct — used only by [`derive_address`]; callers do not
/// need to construct one directly.
#[derive(Serialize)]
struct DerivationInput<'a> {
    creation_tx_hash: &'a TxHash,
    creator_address: &'a Address,
    index: u64,
}

/// Derive an account's [`Address`] from its creation context, per
/// whitepaper section 4.2.
///
/// # Inputs
///
/// - `creation_tx_hash` — hash of the transaction that creates the
///   account. The hashing logic that produces a [`TxHash`] from a
///   transaction lands in `adamant-vm` (Phase 5) when the transaction
///   format itself is specified in whitepaper section 6.
/// - `creator_address` — address of the account that submitted the
///   creation transaction.
/// - `index` — per-creator counter ensuring uniqueness when one
///   creator submits multiple account-creation transactions in the
///   same parent transaction. The counter discipline is the
///   creator's responsibility; this function does not maintain it.
///
/// # Output
///
/// A 32-byte [`Address`] computed as
/// `sha3_256_tagged(ACCOUNT_ADDRESS, BCS(creation_tx_hash, creator_address, index))`.
///
/// # Determinism
///
/// The function is deterministic: identical inputs always produce
/// identical output. This is required by consensus — every validator
/// must derive the same address for the same creation context.
///
/// # Panics
///
/// Cannot panic in practice. The internal `expect` is a contract
/// assertion: BCS encoding of [`DerivationInput`] is fixed-size
/// (32 + 32 + 8 = 72 bytes) and cannot fail — `bcs::to_bytes`
/// returns `Err` only on serialiser-internal failures (allocator
/// exhaustion, custom-error types) that the inputs here cannot
/// trigger. A panic would indicate a defect in BCS or in this
/// crate's `Serialize` derive on [`DerivationInput`], not a runtime
/// failure mode.
#[must_use]
pub fn derive_address(creation_tx_hash: &TxHash, creator_address: &Address, index: u64) -> Address {
    let input = DerivationInput {
        creation_tx_hash,
        creator_address,
        index,
    };
    // BCS encoding cannot fail in practice for a fixed-size struct
    // with no allocations beyond the output buffer. The encoded
    // length is the sum of the field encodings:
    //   32 bytes (TxHash via BigArray, no length prefix)
    // + 32 bytes (Address via BigArray, no length prefix)
    // +  8 bytes (u64 little-endian)
    // = 72 bytes total.
    let bcs_bytes = bcs::to_bytes(&input).expect(
        "DerivationInput is consensus-spec'd as 72 bytes (32 + 32 + 8) per whitepaper 4.2 \
         and BCS canonical encoding never fails for fixed-size types of this shape; if this \
         trips, the spec was changed without updating the type",
    );
    let hash = sha3_256_tagged(&domain::ACCOUNT_ADDRESS, &bcs_bytes);
    Address::from_bytes(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex_literal::hex;

    /// Construct a fixed [`TxHash`] for tests. The byte pattern is
    /// arbitrary but distinctive enough that hex dumps in test output
    /// are unambiguously this value.
    fn fixed_tx_hash() -> TxHash {
        TxHash::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])
    }

    /// Construct a fixed creator [`Address`] for tests.
    fn fixed_creator() -> Address {
        Address::from_bytes([
            0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e,
            0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c,
            0x3d, 0x3e, 0x3f, 0x40,
        ])
    }

    // ---------- determinism ----------

    /// Same inputs produce the same output. This is the protocol's
    /// minimum consensus requirement: every validator must derive
    /// the same address for the same creation context.
    #[test]
    fn derivation_is_deterministic() {
        let a = derive_address(&fixed_tx_hash(), &fixed_creator(), 0);
        let b = derive_address(&fixed_tx_hash(), &fixed_creator(), 0);
        assert_eq!(a, b);
    }

    // ---------- distinct inputs distinguish ----------

    /// Changing the transaction hash produces a different address.
    /// SHA3-256 collision resistance makes this property cryptographic
    /// rather than empirical: a same-output collision would imply a
    /// SHA3-256 break.
    #[test]
    fn distinct_tx_hash_distinguishes() {
        let creator = fixed_creator();
        let a = derive_address(&fixed_tx_hash(), &creator, 0);
        let other_tx_hash = TxHash::from_bytes([0xff; 32]);
        let b = derive_address(&other_tx_hash, &creator, 0);
        assert_ne!(a, b);
    }

    /// Changing the creator address produces a different address.
    #[test]
    fn distinct_creator_distinguishes() {
        let tx = fixed_tx_hash();
        let a = derive_address(&tx, &fixed_creator(), 0);
        let other_creator = Address::from_bytes([0xff; 32]);
        let b = derive_address(&tx, &other_creator, 0);
        assert_ne!(a, b);
    }

    /// Changing the index produces a different address. This is what
    /// makes the per-creator counter enable repeated account creation
    /// without address collision.
    #[test]
    fn distinct_index_distinguishes() {
        let a = derive_address(&fixed_tx_hash(), &fixed_creator(), 0);
        let b = derive_address(&fixed_tx_hash(), &fixed_creator(), 1);
        assert_ne!(a, b);
    }

    // ---------- domain tag bytes ----------

    /// The domain tag is taken from the centralised registry, not
    /// inlined as a string literal. This test pins the registry's
    /// byte string against the whitepaper section 4.2 specification:
    /// renaming, reformatting, or replacing the tag fails this
    /// assertion. Tag changes are consensus rule changes per
    /// whitepaper 3.3.1.
    #[test]
    fn domain_tag_is_registry_value() {
        assert_eq!(
            domain::ACCOUNT_ADDRESS.as_bytes(),
            b"ADAMANT-v1-account-address"
        );
    }

    // ---------- BCS canonicality ----------

    /// The BCS encoding of [`DerivationInput`] matches a manual
    /// concatenation of the three input fields in their canonical
    /// order. Per whitepaper 5.1.8: fixed-size byte arrays encode as
    /// elements in order with no length prefix; `u64` encodes as
    /// little-endian fixed-width 8 bytes; struct fields encode in
    /// source-declaration order with no separators. Concretely:
    ///
    ///   `BCS(input) == tx_hash_bytes (32)
    ///                || creator_bytes (32)
    ///                || index.to_le_bytes() (8)`
    ///
    /// = 72 bytes. This test fails if any of the following changes
    /// silently:
    ///
    /// - Field order in [`DerivationInput`] (re-orders the byte layout).
    /// - The `serde-big-array` encoding for `[u8; 32]` (would change
    ///   the per-field length).
    /// - BCS itself altering its `u64` or struct encoding (it
    ///   shouldn't; the spec is stable; the pin catches drift anyway).
    #[test]
    fn bcs_input_layout_matches_manual_concatenation() {
        let tx_hash = fixed_tx_hash();
        let creator = fixed_creator();
        let index: u64 = 0x0807_0605_0403_0201;

        // BCS-encoded form, via the same code path `derive_address`
        // uses internally.
        let input = DerivationInput {
            creation_tx_hash: &tx_hash,
            creator_address: &creator,
            index,
        };
        let bcs_bytes = bcs::to_bytes(&input).expect("bcs encode");

        // Manually-constructed reference: 32 + 32 + 8 = 72 bytes.
        let mut manual = Vec::with_capacity(72);
        manual.extend_from_slice(tx_hash.as_bytes());
        manual.extend_from_slice(creator.as_bytes());
        manual.extend_from_slice(&index.to_le_bytes());

        assert_eq!(bcs_bytes, manual);
        assert_eq!(bcs_bytes.len(), 32 + 32 + 8);
    }

    // ---------- known-answer regression vector ----------

    /// Known-answer test pinning the canonical wire format for
    /// account-address derivation under fixed inputs. This is the
    /// first protocol-level derivation that hashes consensus-critical
    /// input under a registered domain tag; committing the output
    /// permanently catches any future change — in BCS, in the
    /// tagged-hash construction, in SHA3-256, or in this crate — that
    /// would produce a different address from the same input.
    ///
    /// # Inputs
    ///
    /// - `creation_tx_hash` = `0x01_02_03_..._20` (32 bytes, `1..=32` ascending)
    /// - `creator_address` = `0x21_22_23_..._40` (32 bytes, `33..=64` ascending)
    /// - `index` = `0`
    ///
    /// # Computation a reviewer can verify by hand
    ///
    /// 1. Construct the BCS-encoded input (72 bytes):
    ///    - 32 bytes of the `creation_tx_hash` (`01 02 03 ... 20`)
    ///    - 32 bytes of the `creator_address` (`21 22 23 ... 40`)
    ///    - 8 bytes of `index = 0` little-endian (`00 00 00 00 00 00 00 00`)
    /// 2. Compute the tag prefix
    ///    `prefix = SHA3-256(b"ADAMANT-v1-account-address")` (32 bytes).
    /// 3. Compute the tagged-hash output
    ///    `output = SHA3-256(prefix || prefix || BCS_input)` (32 bytes).
    /// 4. The returned [`Address`] wraps `output` directly.
    ///
    /// The expected bytes below were generated by running this
    /// derivation once and committing the output. A different result
    /// from the same inputs would indicate the protocol's address
    /// wire format has drifted, which is a consensus rule change.
    #[test]
    fn known_answer_regression_vector() {
        let actual = derive_address(&fixed_tx_hash(), &fixed_creator(), 0);
        let expected = Address::from_bytes(hex!(
            "76dd35e96242ef5dec1c5320f53eb2ea2724923e32f64e6843a7edcd8cc474a3"
        ));
        assert_eq!(
            actual, expected,
            "address derivation regression — input/output stable wire format \
             for `derive_address(0x01..0x20, 0x21..0x40, 0)`. If this fails, \
             the protocol's address wire format has drifted; investigate \
             before changing the expected bytes."
        );
    }
}
