//! Poseidon hash helper per whitepaper §3.3.3 (post-amendment
//! instance 31).
//!
//! Phase 6.0 ships the out-of-circuit Poseidon hash surface used
//! by §7.1 (note commitments), §7.1.2 (nullifier derivation), and
//! §7.1.3 (GNCT Merkle hashes). Phase 6.8's validity-circuit work
//! consumes the same parameter set in-circuit; the out-of-circuit
//! and in-circuit hashes are byte-identical by construction (both
//! invoke the `adamant_halo2::poseidon::Hash` surface
//! with identical specification).
//!
//! # Spec basis
//!
//! Whitepaper §3.3.3 (post-amendment) verbatim:
//!
//! > **Parameters.** The protocol uses Poseidon with the following
//! > parameters: prime field of order equal to the **Pallas base
//! > field** (255 bits, matching the native arithmetic of Halo 2
//! > over the Pasta cycle per section 3.9.1), state width of 3
//! > field elements (rate 2, capacity 1), 8 full rounds and 56
//! > partial rounds — the parameters deployed by Zcash Orchard
//! > in production.
//!
//! > **Library.** The reference implementation uses the Poseidon
//! > implementation from `halo2_gadgets` (zcash variant),
//!
//! Adamant consumes the Poseidon implementation through
//! [`adamant_halo2::poseidon`] — Adamant's fork of upstream
//! `halo2_poseidon 0.1.0` per CLAUDE.md §14.4 Decision 1
//! (resolved as Path C2). The algorithmic surface is byte-
//! identical to upstream; behavioural changes are limited to
//! `no_std → std` shape adjustments documented in
//! `crates/adamant-halo2/PROVENANCE.md`.
//! > specifically the `P128Pow5T3` specification with
//! > `ConstantLength` domain — the same parameters deployed by
//! > Zcash Orchard in production.
//!
//! # Out-of-circuit only
//!
//! Per §3.3.3 "Constraint" paragraph:
//!
//! > Poseidon is used only inside zk circuits. It MUST NOT be used
//! > for general protocol hashing outside circuits. Hashes that
//! > cross the circuit/non-circuit boundary use both Poseidon
//! > (inside the circuit) and SHA3-256 (outside), with the circuit
//! > proving consistency between the two representations.
//!
//! This module's [`poseidon_hash`] function exists for the
//! **off-circuit half** of the boundary rule: wallets that need
//! to compute note commitments / nullifiers without running the
//! validity circuit (e.g., scanning the chain to discover their
//! own notes) call this function. The same hash output, computed
//! in-circuit by the validity prover, must byte-match. The
//! parameter set is genesis-fixed; changing it is a hard fork.
//!
//! # Field encoding
//!
//! Pallas's base field is a prime field with characteristic
//! `p ≈ 2^255 + (small)`. Field elements serialize to 32 bytes
//! in little-endian per the Pasta-curves canonical encoding
//! (`pallas::Base::to_repr()`). [`FieldBytes`] is a 32-byte
//! newtype that pins this encoding at the API boundary; callers
//! convert SHA3-256 outputs / scalars / etc. to field elements
//! via the constructors below.

// Phase 6.8b.2 restructured `adamant_halo2::poseidon`: the
// out-of-circuit primitives moved under
// `adamant_halo2::poseidon::primitives::*` (matching upstream
// halo2_gadgets's API path), making room for the in-circuit
// `Pow5Chip` surface at `adamant_halo2::poseidon::*`. Adamant-
// privacy's out-of-circuit Poseidon helper consumes the
// primitives path.
use adamant_halo2::poseidon::primitives::{ConstantLength, Hash, P128Pow5T3};
use pasta_curves::group::ff::PrimeField;
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Byte length of a Pallas-base-field element in canonical
/// little-endian encoding. The protocol's Poseidon output is one
/// field element, so [`POSEIDON_OUTPUT_BYTES`] also equals 32.
pub const POSEIDON_OUTPUT_BYTES: usize = 32;

/// Byte length of an input "field element" passed to
/// [`poseidon_hash`]. Matches [`POSEIDON_OUTPUT_BYTES`] —
/// inputs and outputs live in the same field.
pub const POSEIDON_INPUT_BYTES: usize = 32;

/// Pallas-base-field element in canonical 32-byte little-endian
/// encoding per §3.3.3 amendment.
///
/// `FieldBytes` is the API-boundary type for [`poseidon_hash`]
/// inputs and outputs. Callers convert from raw 32-byte buffers
/// via [`FieldBytes::from_bytes`] (which validates that the
/// bytes encode an element less than the field characteristic);
/// they read raw bytes back via [`FieldBytes::to_bytes`].
///
/// Since the protocol uses Poseidon only at the circuit/non-
/// circuit boundary (per §3.3.3 Constraint), inputs to this
/// function are typically 32-byte SHA3-256 outputs reduced
/// modulo the Pallas base field characteristic. A canonical
/// reduction-from-bytes constructor is provided as
/// [`FieldBytes::from_bytes_reduced`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FieldBytes(#[serde(with = "BigArray")] [u8; POSEIDON_INPUT_BYTES]);

/// Returned by [`FieldBytes::from_bytes`] when the input bytes
/// encode an integer ≥ the Pallas base field characteristic.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FieldOutOfRange;

impl core::fmt::Display for FieldOutOfRange {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("bytes encode an integer ≥ Pallas base field characteristic")
    }
}

impl std::error::Error for FieldOutOfRange {}

impl FieldBytes {
    /// Construct from a 32-byte canonical encoding. Returns
    /// [`FieldOutOfRange`] if the bytes encode an integer ≥ the
    /// Pallas base field characteristic.
    ///
    /// # Errors
    ///
    /// Returns [`FieldOutOfRange`] when the encoded integer is
    /// outside `[0, p)`.
    pub fn from_bytes(bytes: [u8; POSEIDON_INPUT_BYTES]) -> Result<Self, FieldOutOfRange> {
        let opt = pallas::Base::from_repr(bytes);
        if bool::from(opt.is_some()) {
            Ok(Self(bytes))
        } else {
            Err(FieldOutOfRange)
        }
    }

    /// Reduce arbitrary 32 bytes modulo the Pallas base field
    /// characteristic. Useful for converting SHA3-256 hash outputs
    /// (uniform in `[0, 2^256)`) into field elements (uniform in
    /// `[0, p)`).
    ///
    /// The reduction strategy zeroes the top two bits of the
    /// input — `p` for Pallas is `≈ 2^254.86`, so any 254-bit
    /// value is in range. Specifically, the encoding sets bits
    /// 255-254 of byte index 31 to zero before validation. This
    /// loses 2 bits of entropy from the SHA3-256 output but
    /// guarantees the reduction is constant-time and avoids
    /// modular bias for the Phase 6.0–6.7 use sites (note
    /// commitments + nullifier-key derivation), where the input
    /// is already the output of a tagged SHA3-256.
    ///
    /// Phase 6.0 ships this conservative reduction; if benchmarks
    /// or cryptographic review at Phase 6.8 (validity circuit)
    /// indicate a different reduction shape is preferable, the
    /// constructor signature is stable but the reduction-internal
    /// algorithm may evolve. The 2-bit entropy loss is documented
    /// here for traceability.
    #[must_use]
    pub fn from_bytes_reduced(mut bytes: [u8; POSEIDON_INPUT_BYTES]) -> Self {
        // Pallas base field modulus p has top-byte 0x40, so
        // clearing bits 6-7 of byte 31 (little-endian top byte)
        // ensures the value is < p.
        bytes[31] &= 0x3F;
        // Now bytes encode an integer in [0, 2^254), strictly
        // less than p ≈ 2^254.86.
        debug_assert!(bool::from(pallas::Base::from_repr(bytes).is_some()));
        Self(bytes)
    }

    /// Canonical 32-byte little-endian encoding.
    #[must_use]
    pub fn to_bytes(self) -> [u8; POSEIDON_INPUT_BYTES] {
        self.0
    }

    /// Convert to a `pallas::Base` field element. Cannot fail
    /// because [`FieldBytes`] is a validated representation.
    fn to_field(self) -> pallas::Base {
        pallas::Base::from_repr(self.0)
            .expect("FieldBytes invariant: bytes always encode a valid field element")
    }

    /// Wrap a Pallas-base-field element as canonical bytes.
    fn from_field(elem: pallas::Base) -> Self {
        Self(elem.to_repr())
    }
}

/// Compute Poseidon hash of a fixed-length sequence of field
/// elements per whitepaper §3.3.3.
///
/// Returns the single-field-element output as canonical 32-byte
/// little-endian encoding. The hash is genesis-fixed; same input
/// always produces the same output (consensus requirement per
/// §6.2.4).
///
/// # Domain separation
///
/// The `P128Pow5T3` specification with `ConstantLength<L>` domain
/// pads the input to the rate (2) and pre-mixes a length-encoding
/// constant per the Poseidon `ConstantLength` domain rule. Two
/// inputs of different lengths produce uncorrelated outputs by
/// construction. Callers needing further domain separation
/// (e.g., distinguishing note commitments from nullifiers from
/// Merkle path hashes) prepend a domain-tag field element to the
/// input.
///
/// # Const generic
///
/// `L` is the input arity. Common values:
///
/// - `L = 2` for binary Merkle path hashes (§7.1.3).
/// - `L = 5` for note commitments per §7.1
///   (`value || asset_type || recipient || randomness || metadata_hash`).
/// - `L = 4` for nullifiers per §7.1.2
///   (`domain_tag || nullifier_key || note_commitment || position`).
///
/// Other arities are valid; the hash function is parametric over
/// `L`.
#[must_use]
pub fn poseidon_hash<const L: usize>(inputs: [FieldBytes; L]) -> FieldBytes {
    let field_inputs: [pallas::Base; L] = inputs.map(FieldBytes::to_field);
    // RATE = 2, WIDTH = 3 per §3.3.3.
    let hasher = Hash::<pallas::Base, P128Pow5T3, ConstantLength<L>, 3, 2>::init();
    let output: pallas::Base = hasher.hash(field_inputs);
    FieldBytes::from_field(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_halo2::poseidon::primitives::Spec;

    /// Returns `true` iff the [`P128Pow5T3`] specification's
    /// full-round count and partial-round count match the §3.3.3
    /// amended parameters (8 full + 56 partial). Used by the
    /// parameter-pin regression test to catch upstream-library
    /// drift.
    ///
    /// `P128Pow5T3` implements `Spec` for both Pallas's base
    /// field (`pallas::Base = Fp`) and Vesta's base field (`Fq`);
    /// the type annotation pins which impl we're querying. The
    /// round counts are identical for both fields (the same
    /// parameter generation algorithm), so either annotation
    /// works; we use the Pallas annotation to match Adamant's
    /// deployed field per §3.3.3 amendment.
    fn p128pow5t3_matches_spec() -> bool {
        <P128Pow5T3 as Spec<pallas::Base, 3, 2>>::full_rounds() == 8
            && <P128Pow5T3 as Spec<pallas::Base, 3, 2>>::partial_rounds() == 56
    }

    /// Whitepaper §3.3.3 (post-amendment): "8 full rounds and 57
    /// partial rounds." Pin the upstream library's spec against
    /// the spec text. If `adamant-halo2`'s `P128Pow5T3` ever
    /// drifts (e.g., via dep upgrade), this test fails loudly.
    #[test]
    fn p128pow5t3_matches_amended_spec_3_3_3() {
        assert_eq!(<P128Pow5T3 as Spec<pallas::Base, 3, 2>>::full_rounds(), 8);
        assert_eq!(
            <P128Pow5T3 as Spec<pallas::Base, 3, 2>>::partial_rounds(),
            56
        );
        assert!(p128pow5t3_matches_spec());
    }

    #[test]
    fn field_bytes_zero_round_trips() {
        let zero = FieldBytes::from_bytes([0u8; 32]).expect("zero is valid");
        assert_eq!(zero.to_bytes(), [0u8; 32]);
    }

    #[test]
    fn field_bytes_max_canonical_value_accepted() {
        // p - 1 in little-endian (Pallas base field characteristic
        // minus one). Top byte is 0x3F since p has top byte 0x40.
        // Compute via field-side max: 0 - 1 = p - 1.
        let p_minus_one = (-pallas::Base::from(1u64)).to_repr();
        let fb = FieldBytes::from_bytes(p_minus_one).expect("p-1 in range");
        assert_eq!(fb.to_bytes(), p_minus_one);
    }

    #[test]
    fn field_bytes_out_of_range_rejected() {
        // All-ones (2^256 - 1) is well above p ≈ 2^254.86.
        let bytes = [0xFFu8; 32];
        let result = FieldBytes::from_bytes(bytes);
        assert_eq!(result, Err(FieldOutOfRange));
    }

    #[test]
    fn field_bytes_from_bytes_reduced_clears_top_two_bits() {
        let mut bytes = [0xFFu8; 32];
        let fb = FieldBytes::from_bytes_reduced(bytes);
        bytes[31] &= 0x3F;
        assert_eq!(fb.to_bytes(), bytes);
    }

    #[test]
    fn poseidon_hash_deterministic() {
        let input = [
            FieldBytes::from_bytes_reduced([1u8; 32]),
            FieldBytes::from_bytes_reduced([2u8; 32]),
        ];
        let h1 = poseidon_hash::<2>(input);
        let h2 = poseidon_hash::<2>(input);
        assert_eq!(h1, h2);
    }

    #[test]
    fn poseidon_hash_distinct_inputs_distinct_outputs() {
        let a = [
            FieldBytes::from_bytes_reduced([1u8; 32]),
            FieldBytes::from_bytes_reduced([2u8; 32]),
        ];
        let b = [
            FieldBytes::from_bytes_reduced([1u8; 32]),
            FieldBytes::from_bytes_reduced([3u8; 32]),
        ];
        assert_ne!(poseidon_hash::<2>(a), poseidon_hash::<2>(b));
    }

    #[test]
    fn poseidon_hash_input_order_matters() {
        let ab = [
            FieldBytes::from_bytes_reduced([1u8; 32]),
            FieldBytes::from_bytes_reduced([2u8; 32]),
        ];
        let ba = [
            FieldBytes::from_bytes_reduced([2u8; 32]),
            FieldBytes::from_bytes_reduced([1u8; 32]),
        ];
        assert_ne!(poseidon_hash::<2>(ab), poseidon_hash::<2>(ba));
    }

    /// Different arity → different domain → uncorrelated output
    /// even when the prefix matches.
    #[test]
    fn poseidon_hash_different_arity_uncorrelated() {
        let inputs_2 = [
            FieldBytes::from_bytes_reduced([7u8; 32]),
            FieldBytes::from_bytes_reduced([11u8; 32]),
        ];
        let inputs_3 = [
            FieldBytes::from_bytes_reduced([7u8; 32]),
            FieldBytes::from_bytes_reduced([11u8; 32]),
            FieldBytes::from_bytes_reduced([13u8; 32]),
        ];
        let h2 = poseidon_hash::<2>(inputs_2);
        let h3 = poseidon_hash::<3>(inputs_3);
        assert_ne!(h2, h3);
    }

    /// Five-input arity matches the §7.1 note-commitment formula
    /// shape. Pinning the binding here ensures Phase 6.1's note-
    /// commitment derivation has the right hash signature.
    #[test]
    fn poseidon_hash_arity_5_for_note_commitment() {
        let inputs: [FieldBytes; 5] = [
            FieldBytes::from_bytes_reduced([1u8; 32]),
            FieldBytes::from_bytes_reduced([2u8; 32]),
            FieldBytes::from_bytes_reduced([3u8; 32]),
            FieldBytes::from_bytes_reduced([4u8; 32]),
            FieldBytes::from_bytes_reduced([5u8; 32]),
        ];
        let output = poseidon_hash::<5>(inputs);
        // Output is well-formed bytes; non-zero with overwhelming probability.
        assert_ne!(output.to_bytes(), [0u8; 32]);
    }

    /// `FieldBytes` BCS round-trip — the type appears inside §7.1
    /// note commitments and §7.1.2 nullifiers, both of which are
    /// consensus-critical and serialized via BCS per §5.1.8.
    #[test]
    fn field_bytes_bcs_round_trip() {
        let original = FieldBytes::from_bytes_reduced([0xAB; 32]);
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: FieldBytes = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
        // 32 raw bytes; serde-big-array encoding has no length prefix.
        assert_eq!(encoded.len(), 32);
    }
}
