//! Signature wire-format type — the canonical encoding of a
//! protocol signature carried in `AuthEvidence.signatures` per
//! whitepaper sections 6.0.3 and 6.0.7.
//!
//! Per whitepaper section 6.0.7:
//!
//! > "**`Signature`.** A discriminated union over the protocol's
//! > signature schemes (sections 3.4.1 / 3.4.2):
//! >
//! > ```text
//! > Signature {
//! >     Ed25519([u8; 64]),       // BCS variant tag 0x00
//! >     MlDsa65([u8; 3309]),     // BCS variant tag 0x01
//! >     MlDsa87([u8; 4627]),     // BCS variant tag 0x02
//! > }
//! > ```
//! >
//! > The variant set is fixed at genesis. Adding a new signature
//! > scheme is a hard fork. The fixed sizes match the signature
//! > outputs of the schemes specified in section 3.4. Validators
//! > decode signatures by reading the variant tag, then the
//! > appropriate fixed-size byte array."
//!
//! The variant order is consensus-critical: BCS encodes enum
//! variants by ULEB128 tag, with tags assigned by source order.
//! Reordering variants is a hard fork.
//!
//! Verification logic — turning these bytes into a verified
//! signature against a public key — lives in `adamant-crypto`
//! (which does not depend on this crate). This crate carries the
//! wire-format type only; conversion to and from
//! `adamant-crypto::sig_classical::Signature` and
//! `adamant-crypto::sig_pq::Signature` happens at use sites in the
//! account-validation logic.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Ed25519 signature byte length: 64 bytes (whitepaper section
/// 3.4.1, IETF RFC 8032).
pub const ED25519_SIGNATURE_BYTES: usize = 64;

/// ML-DSA-65 signature byte length: 3309 bytes (whitepaper section
/// 3.4.2, NIST FIPS 204 final). Matches
/// `adamant_crypto::sig_pq::SIGNATURE_BYTES`.
pub const ML_DSA_65_SIGNATURE_BYTES: usize = 3309;

/// ML-DSA-87 signature byte length: 4627 bytes (whitepaper section
/// 3.4.2, NIST FIPS 204 final).
pub const ML_DSA_87_SIGNATURE_BYTES: usize = 4627;

/// Wire-format signature for the protocol's authentication schemes
/// (whitepaper section 6.0.7).
///
/// Variant tags pinned by whitepaper 6.0.7:
///
/// - [`Signature::Ed25519`] — BCS variant tag `0x00`
/// - [`Signature::MlDsa65`] — BCS variant tag `0x01`
/// - [`Signature::MlDsa87`] — BCS variant tag `0x02`
///
/// The variant set is fixed at genesis per whitepaper 6.0.7.
/// Adding, removing, or reordering variants is a hard fork.
///
/// # Memory representation
///
/// The in-memory representation carries the largest variant's
/// stack size (4627 bytes per ML-DSA-87) regardless of which
/// variant is in use. This is wasteful for the common Ed25519 case
/// (64 bytes used, 4563 bytes padding). An optimised representation
/// that boxes the larger variants may be introduced in a future
/// commit; such a change would alter the in-memory layout but
/// **not** the BCS wire format, since `serde` descends transparently
/// through `Box<T>`. The wire format is the consensus-critical
/// surface and is pinned by whitepaper 6.0.7; the in-memory layout
/// is an implementation detail.
// `large_enum_variant` is allowed because the size discrepancy is
// inherent to the spec (whitepaper §6.0.7 fixes the variant sizes
// at 64 / 3309 / 4627 bytes) and the boxing-deferred decision is
// documented on the type. The clippy suggestion to box would
// affect in-memory layout but not the BCS wire format, which is
// the consensus surface; the trade-off is reviewed in the type's
// doc comment.
/// Adamant signature wire enum per whitepaper §3.4.
///
/// Variant tags are pinned at genesis-fixed BCS encoding values:
/// `Ed25519 = 0x00` (§3.4.1), `MlDsa65 = 0x01` (§3.4.2 NIST FIPS 204
/// final), `Bls = 0x02` (§3.4.3 BLS12-381 G2 signature).
///
/// The variant-size disparity (Ed25519 64 bytes vs ML-DSA 3309
/// bytes vs BLS 96 bytes) means the in-memory `enum` carries the
/// largest variant's footprint per Rust's enum layout. The
/// `#[allow(clippy::large_enum_variant)]` attribute documents that
/// the trade-off is intentional: boxing would change in-memory
/// layout but NOT the BCS wire format (the consensus surface), so
/// the cleaner direct-enum representation is preferred. If
/// per-transaction allocation pressure ever becomes a measurable
/// bottleneck pre-mainnet, the `Box<MlDsa65SignatureBytes>` shape
/// can be revisited as a non-consensus optimization.
#[allow(clippy::large_enum_variant)]
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Signature {
    /// Ed25519 signature, 64 bytes (whitepaper section 3.4.1).
    /// BCS variant tag `0x00`.
    Ed25519(#[serde(with = "BigArray")] [u8; ED25519_SIGNATURE_BYTES]),
    /// ML-DSA-65 signature, 3309 bytes (whitepaper section 3.4.2,
    /// NIST FIPS 204 final). BCS variant tag `0x01`.
    MlDsa65(#[serde(with = "BigArray")] [u8; ML_DSA_65_SIGNATURE_BYTES]),
    /// ML-DSA-87 signature, 4627 bytes (whitepaper section 3.4.2,
    /// NIST FIPS 204 final). BCS variant tag `0x02`.
    MlDsa87(#[serde(with = "BigArray")] [u8; ML_DSA_87_SIGNATURE_BYTES]),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn declared_sizes_match_whitepaper() {
        assert_eq!(ED25519_SIGNATURE_BYTES, 64);
        assert_eq!(ML_DSA_65_SIGNATURE_BYTES, 3309);
        assert_eq!(ML_DSA_87_SIGNATURE_BYTES, 4627);
    }

    /// Ed25519 variant encodes as `0x00 || 64 bytes`. The variant
    /// tag `0x00` is consensus-critical per whitepaper 6.0.7.
    #[test]
    fn ed25519_variant_tag_and_size() {
        let sig = Signature::Ed25519([0x42; ED25519_SIGNATURE_BYTES]);
        let encoded = bcs::to_bytes(&sig).expect("bcs encode");
        assert_eq!(encoded[0], 0x00, "Ed25519 BCS variant tag must be 0x00");
        assert_eq!(encoded.len(), 1 + ED25519_SIGNATURE_BYTES);
        assert_eq!(&encoded[1..], &[0x42; ED25519_SIGNATURE_BYTES]);
    }

    /// ML-DSA-65 variant encodes as `0x01 || 3309 bytes`.
    #[test]
    fn ml_dsa_65_variant_tag_and_size() {
        let sig = Signature::MlDsa65([0x33; ML_DSA_65_SIGNATURE_BYTES]);
        let encoded = bcs::to_bytes(&sig).expect("bcs encode");
        assert_eq!(encoded[0], 0x01, "MlDsa65 BCS variant tag must be 0x01");
        assert_eq!(encoded.len(), 1 + ML_DSA_65_SIGNATURE_BYTES);
    }

    /// ML-DSA-87 variant encodes as `0x02 || 4627 bytes`.
    #[test]
    fn ml_dsa_87_variant_tag_and_size() {
        let sig = Signature::MlDsa87([0x77; ML_DSA_87_SIGNATURE_BYTES]);
        let encoded = bcs::to_bytes(&sig).expect("bcs encode");
        assert_eq!(encoded[0], 0x02, "MlDsa87 BCS variant tag must be 0x02");
        assert_eq!(encoded.len(), 1 + ML_DSA_87_SIGNATURE_BYTES);
    }

    /// Each variant survives a roundtrip; decoding produces the
    /// same variant with the same payload.
    #[test]
    fn bcs_round_trip_each_variant() {
        let cases = [
            Signature::Ed25519([0xab; ED25519_SIGNATURE_BYTES]),
            Signature::MlDsa65([0xcd; ML_DSA_65_SIGNATURE_BYTES]),
            Signature::MlDsa87([0xef; ML_DSA_87_SIGNATURE_BYTES]),
        ];
        for sig in cases {
            let encoded = bcs::to_bytes(&sig).expect("bcs encode");
            let decoded: Signature = bcs::from_bytes(&encoded).expect("bcs decode");
            assert_eq!(decoded, sig);
        }
    }

    /// Variants with the same payload bytes but different schemes
    /// are not equal — the variant tag distinguishes them. This
    /// pins the property that a payload-collision across schemes
    /// (which is cryptographically vanishingly unlikely but
    /// type-theoretically possible) does not collapse two distinct
    /// signatures into the same value.
    #[test]
    fn distinct_variants_are_unequal() {
        // Same first 64 bytes; different variants.
        let mut buf65 = [0u8; ML_DSA_65_SIGNATURE_BYTES];
        let mut buf87 = [0u8; ML_DSA_87_SIGNATURE_BYTES];
        buf65[..64].copy_from_slice(&[0x99; 64]);
        buf87[..64].copy_from_slice(&[0x99; 64]);
        let a = Signature::Ed25519([0x99; 64]);
        let b = Signature::MlDsa65(buf65);
        let c = Signature::MlDsa87(buf87);
        assert_ne!(a, b);
        assert_ne!(b, c);
        assert_ne!(a, c);
    }
}
