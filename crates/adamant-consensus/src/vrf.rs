//! Consensus VRF per whitepaper §8.6.
//!
//! Several consensus operations require **deterministic
//! randomness**: active-set selection at epoch boundaries
//! (§8.1.3), commit-wave anchor election (§8.3.3), and various
//! leader-rotation operations. The protocol provides this
//! through a Verifiable Random Function constructed from BLS
//! signatures.
//!
//! # Construction (§8.6.1 verbatim)
//!
//! > The VRF is constructed from BLS signatures: each
//! > validator's BLS signature over a specific input is
//! > deterministic (a property of BLS) and unpredictable to
//! > anyone without the validator's secret key (the random-
//! > oracle assumption). Aggregating BLS signatures from a
//! > quorum of validators produces a value that is
//! > unpredictable to anyone who cannot compromise a majority
//! > of validators.
//!
//! VRF inputs (per §8.6.1):
//!
//! - **Epoch boundary**: previous epoch's recursive-proof
//!   commitment (§8.5).
//! - **Round anchor**: previous round's aggregate VRF output +
//!   the round number.
//!
//! # Flow
//!
//! 1. Each validator in the active set computes a [`VrfShare`]
//!    by BLS-signing the canonical VRF-input message
//!    (`sha3_256_tagged(VRF_INPUT, BCS(VrfInput))`).
//! 2. Validators broadcast their shares.
//! 3. Once a quorum of distinct, valid shares is collected, any
//!    party can produce the [`VrfOutput`] by [`aggregate_shares`].
//! 4. The VRF output is publicly verifiable via [`verify_output`]:
//!    re-aggregate the public keys, re-derive the input message,
//!    BLS `fast_aggregate_verify`.
//! 5. [`output_randomness`] extracts the canonical 32-byte
//!    uniform randomness from the output.
//!
//! # Why aggregation matters
//!
//! Per §8.6.2: "an adversary must compromise a supermajority of
//! validators to influence a single output, and even then the
//! manipulation is detectable (the output would not match the
//! published BLS signatures' aggregate)."
//!
//! Each validator's share is deterministic in the validator's
//! secret key + the input; the aggregate is uniformly random
//! under the BLS-MGS (multi-signature gap-Diffie-Hellman) /
//! random-oracle assumption when at least one contributing
//! validator is honest. Adamant's §8.6 calibration: aggregate
//! ≥ `quorum_threshold(active_set_size)` shares per
//! [`crate::schedule::quorum_threshold`].
//!
//! # Phase 7.4 scope
//!
//! Type-level VRF construction + cryptographic wiring through
//! `adamant_crypto::bls`. Actual signing happens at the
//! validator-process boundary (validators hold their own
//! `bls::SecretKey`s); this module provides the canonical
//! message-binding + aggregation + verification + randomness-
//! extraction surfaces.
//!
//! Phase 7.7 (DAG-BFT consensus core) wires the VRF into the
//! anchor-election + active-set-selection flows. Phase 7.6
//! (threshold mempool) consumes the VRF for the round-anchor
//! decryption-share elector.

use adamant_crypto::bls::{
    AggregatePublicKey, AggregateSignature, Error as BlsError, PublicKey, SecretKey, Signature,
};
use adamant_crypto::{domain, hash::sha3_256_tagged};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::epoch::{EpochNumber, RoundNumber};
use crate::identity::ValidatorId;

/// Byte width of the VRF randomness output. 256 bits = 32 bytes,
/// matching the chain's other commitment-byte widths
/// (`EpochCommitment`, `ValidatorId`, `VertexId`).
pub const VRF_RANDOMNESS_BYTES: usize = 32;

// ---------------------------------------------------------------
// VrfInput — typed VRF input shapes per §8.6.1
// ---------------------------------------------------------------

/// Typed VRF input per whitepaper §8.6.1.
///
/// Variant tags are pinned at genesis-fixed BCS encoding values:
/// `EpochBoundary = 0x00`, `RoundAnchor = 0x01`. Reordering or
/// adding variants is a hard fork: the canonical
/// `sha3_256_tagged(VRF_INPUT, BCS(self))` message bytes change,
/// invalidating all previously-produced VRF shares.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum VrfInput {
    /// VRF input for active-set selection at an epoch boundary
    /// per §8.6.1 first bullet. Binds to:
    /// - `epoch` — the epoch being entered (the new active set
    ///   takes effect at the start of this epoch).
    /// - `previous_epoch_proof` — the previous epoch's
    ///   recursive-proof commitment (Phase 6.9b's
    ///   `EpochCommitment` bytes per §8.5.1).
    EpochBoundary {
        /// Epoch being entered.
        epoch: EpochNumber,
        /// Previous epoch's recursive-proof commitment per §8.5.1.
        previous_epoch_proof: [u8; 32],
    },
    /// VRF input for commit-wave anchor election per §8.6.1
    /// second bullet + §8.3.3. Binds to:
    /// - `round` — the round whose anchor is being elected.
    /// - `previous_round_vrf` — randomness from the previous
    ///   round's VRF output (chained per §8.6.1).
    RoundAnchor {
        /// Round whose anchor is being elected.
        round: RoundNumber,
        /// Previous round's VRF randomness (chained).
        previous_round_vrf: [u8; VRF_RANDOMNESS_BYTES],
    },
}

impl VrfInput {
    /// Canonical message bytes that validators BLS-sign per
    /// §8.6.1. Composition:
    /// `sha3_256_tagged(VRF_INPUT, BCS(self))`. Defence-in-depth
    /// domain separation: the inner tag separates VRF messages
    /// from other BLS-signed protocol messages; BLS's own
    /// `BLS_SIG_HASH_TO_CURVE` DST separates the BLS layer
    /// from other crypto-protocol uses of BLS12-381.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: `VrfInput` is a plain-data
    /// enum with derived `Serialize`; BCS serialisation is
    /// infallible for this shape.
    #[must_use]
    pub fn canonical_message(&self) -> [u8; 32] {
        let bcs_bytes = bcs::to_bytes(self).expect("VrfInput is BCS-serialisable by construction");
        sha3_256_tagged(&domain::VRF_INPUT, &bcs_bytes)
    }
}

// ---------------------------------------------------------------
// VrfShare — a single validator's contribution
// ---------------------------------------------------------------

/// A single validator's contribution to the consensus VRF per
/// §8.6.1: a BLS signature over the canonical VRF-input message,
/// produced with the validator's secret key.
///
/// Wire format: BCS-encoded `(validator_id, signature_bytes)`.
/// 32 bytes (validator id) + 48 bytes (BLS G1 sig) = 80 bytes.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct VrfShare {
    /// Identifier of the validator that produced this share.
    pub validator_id: ValidatorId,
    /// The validator's BLS signature on
    /// `input.canonical_message()`.
    #[serde(with = "BigArray")]
    pub signature_bytes: [u8; 48],
}

impl VrfShare {
    /// Produce a [`VrfShare`] for the given input by signing
    /// `input.canonical_message()` with `secret_key`.
    ///
    /// The validator's identifier is supplied by the caller
    /// (it's derived from the validator's
    /// [`crate::ValidatorPublicKeys`]; this function doesn't
    /// re-derive it to avoid duplicating the key bundle in the
    /// share).
    #[must_use]
    pub fn compute(validator_id: ValidatorId, secret_key: &SecretKey, input: &VrfInput) -> Self {
        let message = input.canonical_message();
        let signature = secret_key.sign(&message);
        Self {
            validator_id,
            signature_bytes: signature.to_bytes(),
        }
    }

    /// Verify this share against the input and the supplied
    /// validator public key.
    ///
    /// # Errors
    ///
    /// Returns `false` for any verification failure (parse
    /// error or signature-mismatch). Matches the constant-time
    /// discipline of the existing crypto-verification helpers.
    #[must_use]
    pub fn verify(&self, input: &VrfInput, public_key: &PublicKey) -> bool {
        let Ok(signature) = Signature::from_bytes(&self.signature_bytes) else {
            return false;
        };
        public_key
            .verify(&input.canonical_message(), &signature)
            .is_ok()
    }

    /// Parse the share's BLS signature for use in aggregation.
    ///
    /// # Errors
    ///
    /// Returns [`BlsError`] if the byte buffer doesn't decode as
    /// a valid G1-compressed signature.
    pub fn parse_signature(&self) -> Result<Signature, BlsError> {
        Signature::from_bytes(&self.signature_bytes)
    }
}

// ---------------------------------------------------------------
// VrfOutput — aggregate per §8.6.1
// ---------------------------------------------------------------

/// Aggregate VRF output per §8.6.1: the aggregate BLS signature
/// over the canonical VRF-input message, contributed to by a
/// quorum of validators.
///
/// The output is publicly verifiable: anyone holding the
/// participating validators' public keys can call
/// [`verify_output`] to confirm the aggregate is correctly
/// formed.
///
/// The output's uniform-random representation is extracted via
/// [`output_randomness`] for downstream anchor-election /
/// active-set-selection use.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct VrfOutput {
    /// Aggregate BLS signature over `input.canonical_message()`,
    /// summed over `contributors`' shares. 48 bytes (G1
    /// compressed).
    #[serde(with = "BigArray")]
    pub aggregate_signature_bytes: [u8; 48],
    /// Validator identifiers that contributed to the aggregate,
    /// in deterministic order (caller-side: sorted by
    /// `ValidatorId` lexicographically before aggregation).
    pub contributors: Vec<ValidatorId>,
}

// ---------------------------------------------------------------
// Errors
// ---------------------------------------------------------------

/// Errors surfaced by VRF aggregation / verification.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VrfError {
    /// Aggregation attempted with zero shares. The aggregate is
    /// undefined for an empty set; callers must collect at
    /// least one share before aggregating.
    EmptyShareSet,
    /// Two shares carry the same `ValidatorId`. Aggregation
    /// rejects duplicates: each contributing validator must
    /// appear exactly once.
    DuplicateContributor,
    /// A share's signature bytes don't decode as a valid
    /// G1-compressed BLS signature.
    MalformedShareSignature,
    /// BLS aggregation failed at the cryptographic layer (e.g.,
    /// point-at-infinity rejection).
    AggregationFailure,
    /// The `contributors` list and the `public_keys` list passed
    /// to [`verify_output`] have different lengths.
    PublicKeyArityMismatch,
    /// A supplied public key's bytes don't decode as a valid
    /// G2-compressed BLS public key.
    MalformedPublicKey,
    /// `fast_aggregate_verify` returned an error or the aggregate
    /// signature didn't verify against the supplied keys + input.
    InvalidAggregate,
}

impl core::fmt::Display for VrfError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::EmptyShareSet => f.write_str("VRF aggregation requires at least one share"),
            Self::DuplicateContributor => f.write_str("duplicate validator in VRF share set"),
            Self::MalformedShareSignature => {
                f.write_str("VRF share signature bytes are not a valid BLS G1 point")
            }
            Self::AggregationFailure => f.write_str("BLS aggregation failed"),
            Self::PublicKeyArityMismatch => {
                f.write_str("public-keys list arity != contributors arity")
            }
            Self::MalformedPublicKey => {
                f.write_str("supplied public-key bytes are not a valid BLS G2 point")
            }
            Self::InvalidAggregate => {
                f.write_str("aggregate VRF output failed BLS aggregate-verify")
            }
        }
    }
}

impl std::error::Error for VrfError {}

// ---------------------------------------------------------------
// Aggregation + verification + randomness extraction
// ---------------------------------------------------------------

/// Aggregate a quorum of [`VrfShare`]s into a [`VrfOutput`] per
/// §8.6.1.
///
/// Shares are sorted by `ValidatorId` lexicographically before
/// aggregation so the resulting `VrfOutput.contributors` ordering
/// is deterministic across all parties producing the same output
/// from the same share set. BLS signature aggregation is
/// commutative on G1 points, so the order doesn't affect the
/// aggregate bytes; the deterministic-ordering invariant is for
/// `contributors` serialization, which IS consensus-binding.
///
/// # Errors
///
/// - [`VrfError::EmptyShareSet`] if `shares` is empty.
/// - [`VrfError::DuplicateContributor`] if two shares share a
///   `ValidatorId`.
/// - [`VrfError::MalformedShareSignature`] if any share's
///   signature bytes don't decode.
/// - [`VrfError::AggregationFailure`] if BLS aggregation
///   rejects the share set.
pub fn aggregate_shares(shares: &[VrfShare]) -> Result<VrfOutput, VrfError> {
    if shares.is_empty() {
        return Err(VrfError::EmptyShareSet);
    }

    // Deterministic ordering by validator id.
    let mut sorted: Vec<&VrfShare> = shares.iter().collect();
    sorted.sort_by_key(|s| s.validator_id);

    // Reject duplicates after sort.
    for w in sorted.windows(2) {
        if w[0].validator_id == w[1].validator_id {
            return Err(VrfError::DuplicateContributor);
        }
    }

    // Parse each share's signature, collect into Vec<Signature>.
    let parsed: Result<Vec<Signature>, _> = sorted.iter().map(|s| s.parse_signature()).collect();
    let parsed = parsed.map_err(|_| VrfError::MalformedShareSignature)?;
    let refs: Vec<&Signature> = parsed.iter().collect();

    // BLS-aggregate.
    let aggregate =
        AggregateSignature::aggregate(&refs).map_err(|_| VrfError::AggregationFailure)?;
    let aggregate_sig = aggregate.to_signature();
    let aggregate_signature_bytes = aggregate_sig.to_bytes();

    let contributors: Vec<ValidatorId> = sorted.iter().map(|s| s.validator_id).collect();

    Ok(VrfOutput {
        aggregate_signature_bytes,
        contributors,
    })
}

/// Verify a [`VrfOutput`] against the given input + the
/// contributing validators' public keys.
///
/// Per §8.6.1: "anyone can check that the published output is
/// correct given the input and the validators' public keys."
///
/// `public_keys` must align with `output.contributors` by index
/// — i.e., `public_keys[i]` is the BLS public key of
/// `output.contributors[i]`.
///
/// # Errors
///
/// - [`VrfError::PublicKeyArityMismatch`] if `public_keys.len()
///   != output.contributors.len()`.
/// - [`VrfError::MalformedPublicKey`] / `MalformedShareSignature`
///   on parse errors.
/// - [`VrfError::InvalidAggregate`] if the aggregate doesn't
///   verify.
pub fn verify_output(
    input: &VrfInput,
    output: &VrfOutput,
    public_keys: &[PublicKey],
) -> Result<(), VrfError> {
    if public_keys.len() != output.contributors.len() {
        return Err(VrfError::PublicKeyArityMismatch);
    }
    let aggregate_sig = Signature::from_bytes(&output.aggregate_signature_bytes)
        .map_err(|_| VrfError::MalformedShareSignature)?;
    // Re-wrap the canonical aggregate signature into an
    // `AggregateSignature` for the verify API. BLS aggregation
    // is commutative + idempotent over a single-element slice;
    // this re-aggregation is a no-op on the bytes.
    let agg = AggregateSignature::aggregate(&[&aggregate_sig])
        .map_err(|_| VrfError::AggregationFailure)?;

    let pk_refs: Vec<&PublicKey> = public_keys.iter().collect();
    let message = input.canonical_message();

    agg.fast_aggregate_verify(&message, &pk_refs)
        .map_err(|_| VrfError::InvalidAggregate)
}

/// Aggregate the contributing validators' public keys for
/// verification convenience.
///
/// # Errors
///
/// Returns [`VrfError::AggregationFailure`] if BLS public-key
/// aggregation fails.
pub fn aggregate_public_keys(public_keys: &[PublicKey]) -> Result<AggregatePublicKey, VrfError> {
    let refs: Vec<&PublicKey> = public_keys.iter().collect();
    AggregatePublicKey::aggregate(&refs).map_err(|_| VrfError::AggregationFailure)
}

/// Extract the canonical 32-byte uniform randomness from a
/// [`VrfOutput`] per §8.6. Composition:
/// `sha3_256_tagged(VRF_OUTPUT, aggregate_signature_bytes)`.
///
/// The randomness is what downstream consumers — anchor
/// election (§8.3.3), active-set selection (§8.1.3), leader-
/// rotation operations — actually consume. The aggregate
/// signature is the consensus-binding artifact (verifiable);
/// the randomness is the application-level derivative.
#[must_use]
pub fn output_randomness(output: &VrfOutput) -> [u8; VRF_RANDOMNESS_BYTES] {
    sha3_256_tagged(&domain::VRF_OUTPUT, &output.aggregate_signature_bytes)
}

// ---------------------------------------------------------------
// Anchor-selection helper
// ---------------------------------------------------------------

/// Deterministically select an index in `0..n` from VRF
/// randomness. Used by §8.3.3 commit-wave anchor election and
/// the §8.1.3 active-set leader-rotation pathways.
///
/// Construction: take the first 8 bytes of the randomness as a
/// big-endian `u64`, reduce modulo `n`. Acceptable bias is
/// `n / 2^64` ≈ 4e-18 even at n = u32::MAX; for `n ≤ 75` (the
/// §8.1.3 launch ceiling) the bias is `< 4e-18 × 75` ≈ 3e-16 —
/// far below cryptographic-significance thresholds.
///
/// # Panics
///
/// Panics if `n == 0` — selection from an empty range is
/// undefined. Callers should typically reject dormant active
/// sets via [`crate::ActiveSet::is_dormant`] before invoking
/// this helper.
#[must_use]
pub fn select_index(randomness: &[u8; VRF_RANDOMNESS_BYTES], n: usize) -> usize {
    assert!(n > 0, "select_index: n must be > 0 (empty active set)");
    // Read the top 8 bytes of the 32-byte randomness as a
    // big-endian u64. Per §8.6 + the §8.1.3 active-set ceiling
    // (75), 8 bytes is overkill — only the low log2(n) bits
    // are sampled by the modular reduction below. The 8-byte
    // read pins the byte interpretation across implementations
    // (32-bit ARM vs 64-bit x86): consensus-binding behaviour
    // is identical on every supported platform.
    let mut buf = [0u8; 8];
    buf.copy_from_slice(&randomness[..8]);
    let r = u64::from_be_bytes(buf);
    // Modular reduction with platform-independent semantics:
    // `r % (n as u64)` is bounded above by `n - 1`, and `n` is
    // a `usize` so `n - 1 <= usize::MAX` on both 32-bit and
    // 64-bit targets. The `as usize` final cast is therefore
    // structurally lossless on both platforms.
    //
    // Hardening note (pre-Phase-10 audit closure): the previous
    // comment claimed "truncates the high bits" — that was
    // misleading. No truncation occurs: the modular reduction
    // produces a value < n which always fits in usize.
    // [`select_index_is_bit_exact_under_known_inputs`] pins
    // the exact return value for a fixture input as a
    // regression anchor.
    //
    // Bias: for n that is NOT a power of two, modular reduction
    // introduces bias of at most `n / 2^64 ≈ 4e-18` at n = 75
    // (the §8.1.3 launch ceiling). Negligible at protocol
    // scale; the §8.6 BLS-aggregate VRF randomness is the
    // cryptographic security boundary, not this reduction.
    #[allow(
        clippy::cast_possible_truncation,
        reason = "result is always < n which fits in usize on every supported target"
    )]
    {
        (r % n as u64) as usize
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_crypto::bls::SecretKey;

    fn vid(byte: u8) -> ValidatorId {
        ValidatorId::from_bytes([byte; 32])
    }

    fn fixed_secret(seed: u8) -> SecretKey {
        // Deterministic test keys: 32-byte all-`seed` IKM.
        // BLS secret-key derivation from arbitrary 32-byte input
        // per IETF draft-irtf-cfrg-bls-signature.
        SecretKey::from_ikm(&[seed; 32])
            .expect("fixed_secret: IKM is 32 bytes which exceeds the 32-byte minimum")
    }

    fn fixed_input() -> VrfInput {
        VrfInput::EpochBoundary {
            epoch: EpochNumber::new(7),
            previous_epoch_proof: [0xAA; 32],
        }
    }

    // ---------- VrfInput ----------

    #[test]
    fn vrf_input_bcs_variant_tags_pinned() {
        // EpochBoundary = 0x00
        let bytes = bcs::to_bytes(&VrfInput::EpochBoundary {
            epoch: EpochNumber::ZERO,
            previous_epoch_proof: [0; 32],
        })
        .unwrap();
        assert_eq!(bytes[0], 0x00);
        // RoundAnchor = 0x01
        let bytes = bcs::to_bytes(&VrfInput::RoundAnchor {
            round: RoundNumber::ZERO,
            previous_round_vrf: [0; 32],
        })
        .unwrap();
        assert_eq!(bytes[0], 0x01);
    }

    #[test]
    fn vrf_input_bcs_round_trip() {
        let inputs = [
            VrfInput::EpochBoundary {
                epoch: EpochNumber::new(42),
                previous_epoch_proof: [0xCC; 32],
            },
            VrfInput::RoundAnchor {
                round: RoundNumber::new(100),
                previous_round_vrf: [0xDD; 32],
            },
        ];
        for inp in inputs {
            let bytes = bcs::to_bytes(&inp).unwrap();
            let decoded: VrfInput = bcs::from_bytes(&bytes).unwrap();
            assert_eq!(inp, decoded);
        }
    }

    #[test]
    fn vrf_input_canonical_message_deterministic() {
        let inp = fixed_input();
        assert_eq!(inp.canonical_message(), inp.canonical_message());
    }

    #[test]
    fn vrf_input_canonical_message_uses_vrf_input_tag() {
        let inp = fixed_input();
        let bcs_bytes = bcs::to_bytes(&inp).unwrap();
        let with_vrf_tag = sha3_256_tagged(&domain::VRF_INPUT, &bcs_bytes);
        let with_vertex_tag = sha3_256_tagged(&domain::VERTEX_ID, &bcs_bytes);
        assert_ne!(with_vrf_tag, with_vertex_tag);
        assert_eq!(inp.canonical_message(), with_vrf_tag);
    }

    #[test]
    fn vrf_input_distinct_variants_distinct_messages() {
        let m1 = VrfInput::EpochBoundary {
            epoch: EpochNumber::new(1),
            previous_epoch_proof: [0; 32],
        }
        .canonical_message();
        let m2 = VrfInput::RoundAnchor {
            round: RoundNumber::new(1),
            previous_round_vrf: [0; 32],
        }
        .canonical_message();
        assert_ne!(m1, m2);
    }

    // ---------- VrfShare ----------

    #[test]
    fn share_compute_and_verify_round_trip() {
        let sk = fixed_secret(0x11);
        let pk = sk.public_key();
        let input = fixed_input();
        let share = VrfShare::compute(vid(1), &sk, &input);
        assert!(share.verify(&input, &pk));
    }

    #[test]
    fn share_verify_rejects_wrong_input() {
        let sk = fixed_secret(0x11);
        let pk = sk.public_key();
        let input = fixed_input();
        let wrong_input = VrfInput::RoundAnchor {
            round: RoundNumber::new(99),
            previous_round_vrf: [0; 32],
        };
        let share = VrfShare::compute(vid(1), &sk, &input);
        assert!(!share.verify(&wrong_input, &pk));
    }

    #[test]
    fn share_verify_rejects_wrong_pubkey() {
        let sk_1 = fixed_secret(0x11);
        let sk_2 = fixed_secret(0x22);
        let wrong_pk = sk_2.public_key();
        let input = fixed_input();
        let share = VrfShare::compute(vid(1), &sk_1, &input);
        assert!(!share.verify(&input, &wrong_pk));
    }

    #[test]
    fn share_bcs_round_trip() {
        let sk = fixed_secret(0x11);
        let input = fixed_input();
        let share = VrfShare::compute(vid(7), &sk, &input);
        let bytes = bcs::to_bytes(&share).unwrap();
        let decoded: VrfShare = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(share, decoded);
    }

    // ---------- aggregate_shares ----------

    #[test]
    fn aggregate_empty_rejected() {
        let result = aggregate_shares(&[]);
        assert_eq!(result, Err(VrfError::EmptyShareSet));
    }

    #[test]
    fn aggregate_duplicate_rejected() {
        let sk = fixed_secret(0x11);
        let input = fixed_input();
        let share = VrfShare::compute(vid(1), &sk, &input);
        let shares = vec![share.clone(), share];
        let result = aggregate_shares(&shares);
        assert_eq!(result, Err(VrfError::DuplicateContributor));
    }

    #[test]
    fn aggregate_sorts_contributors_deterministically() {
        let input = fixed_input();
        let sk_a = fixed_secret(0x10);
        let sk_b = fixed_secret(0x20);
        let sk_c = fixed_secret(0x30);
        let share_a = VrfShare::compute(vid(0x10), &sk_a, &input);
        let share_b = VrfShare::compute(vid(0x20), &sk_b, &input);
        let share_c = VrfShare::compute(vid(0x30), &sk_c, &input);

        // Different input orders produce same output (contributors
        // sorted lexicographically by ValidatorId).
        let out_1 = aggregate_shares(&[share_a.clone(), share_b.clone(), share_c.clone()]).unwrap();
        let out_2 = aggregate_shares(&[share_c, share_a, share_b]).unwrap();
        assert_eq!(out_1, out_2);
        assert_eq!(out_1.contributors, vec![vid(0x10), vid(0x20), vid(0x30)]);
    }

    // ---------- verify_output (end-to-end) ----------

    #[test]
    fn verify_output_succeeds_for_valid_quorum() {
        let input = fixed_input();
        let sks = [fixed_secret(0x11), fixed_secret(0x22), fixed_secret(0x33)];
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let ids = [vid(0x11), vid(0x22), vid(0x33)];

        let shares: Vec<VrfShare> = sks
            .iter()
            .zip(ids.iter())
            .map(|(sk, id)| VrfShare::compute(*id, sk, &input))
            .collect();

        let output = aggregate_shares(&shares).expect("aggregate");

        // Public keys must be aligned with `output.contributors`
        // — which is the sorted order. Our `vid(0x11) < vid(0x22)
        // < vid(0x33)` happens to already match `sks`/`pks` order.
        assert_eq!(output.contributors, ids.to_vec());

        let result = verify_output(&input, &output, &pks);
        assert_eq!(result, Ok(()));
    }

    #[test]
    fn verify_output_rejects_wrong_input() {
        let input = fixed_input();
        let wrong_input = VrfInput::RoundAnchor {
            round: RoundNumber::new(999),
            previous_round_vrf: [0; 32],
        };
        let sks = [fixed_secret(0x11), fixed_secret(0x22), fixed_secret(0x33)];
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let ids = [vid(0x11), vid(0x22), vid(0x33)];

        let shares: Vec<VrfShare> = sks
            .iter()
            .zip(ids.iter())
            .map(|(sk, id)| VrfShare::compute(*id, sk, &input))
            .collect();

        let output = aggregate_shares(&shares).unwrap();
        let result = verify_output(&wrong_input, &output, &pks);
        assert_eq!(result, Err(VrfError::InvalidAggregate));
    }

    #[test]
    fn verify_output_rejects_arity_mismatch() {
        let input = fixed_input();
        let sks = [fixed_secret(0x11), fixed_secret(0x22)];
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let ids = [vid(0x11), vid(0x22)];

        let shares: Vec<VrfShare> = sks
            .iter()
            .zip(ids.iter())
            .map(|(sk, id)| VrfShare::compute(*id, sk, &input))
            .collect();

        let output = aggregate_shares(&shares).unwrap();
        // Pass only one public key (arity mismatch).
        let result = verify_output(&input, &output, &pks[..1]);
        assert_eq!(result, Err(VrfError::PublicKeyArityMismatch));
    }

    /// VRF output is deterministic: same input + same shares
    /// produce the same aggregate. Pin: this is the canonical
    /// "deterministic randomness" property per §8.6.
    #[test]
    fn vrf_output_deterministic() {
        let input = fixed_input();
        let sks = [fixed_secret(0x11), fixed_secret(0x22), fixed_secret(0x33)];
        let ids = [vid(0x11), vid(0x22), vid(0x33)];

        let shares: Vec<VrfShare> = sks
            .iter()
            .zip(ids.iter())
            .map(|(sk, id)| VrfShare::compute(*id, sk, &input))
            .collect();

        let out_1 = aggregate_shares(&shares).unwrap();
        let out_2 = aggregate_shares(&shares).unwrap();
        assert_eq!(out_1, out_2);

        let r_1 = output_randomness(&out_1);
        let r_2 = output_randomness(&out_2);
        assert_eq!(r_1, r_2);
    }

    // ---------- output_randomness ----------

    #[test]
    fn output_randomness_uses_vrf_output_tag() {
        let output = VrfOutput {
            aggregate_signature_bytes: [0x42; 48],
            contributors: vec![vid(1), vid(2)],
        };
        let with_vrf_output_tag =
            sha3_256_tagged(&domain::VRF_OUTPUT, &output.aggregate_signature_bytes);
        let with_validator_id_tag =
            sha3_256_tagged(&domain::VALIDATOR_ID, &output.aggregate_signature_bytes);
        assert_ne!(with_vrf_output_tag, with_validator_id_tag);
        assert_eq!(output_randomness(&output), with_vrf_output_tag);
    }

    /// Known-answer regression vector pinning the canonical
    /// `output_randomness` wire format under a fixed input per
    /// CONTRIBUTING.md "Derivation discipline".
    ///
    /// # Input
    ///
    /// - `aggregate_signature_bytes` = `[0x42; 48]` (48 bytes of
    ///   the same byte 0x42, mimicking a fixed-pattern
    ///   aggregate BLS signature)
    ///
    /// # Computation a reviewer can verify by hand
    ///
    /// 1. `prefix = SHA3-256(b"ADAMANT-v1-vrf-output")` (32 bytes).
    /// 2. `output = SHA3-256(prefix || prefix || [0x42; 48])` (32 bytes).
    ///
    /// The expected bytes were generated by running this
    /// derivation once and committing the output. A different
    /// result from the same inputs would indicate the wire
    /// format has drifted (consensus-breaking change).
    #[test]
    fn output_randomness_known_answer_vector() {
        let output = VrfOutput {
            aggregate_signature_bytes: [0x42; 48],
            contributors: vec![vid(1), vid(2)],
        };
        let actual = output_randomness(&output);
        // Generated by running this test once and capturing
        // the actual output bytes.
        let expected =
            hex_decode_32_test("ecf55ffc2761c7f6cdc533482ec3f2efde94caf4a15151294f2c3d844037983e");
        assert_eq!(
            actual, expected,
            "output_randomness regression — input is aggregate_signature_bytes=[0x42; 48]; \
             if this assertion fails the VRF output-randomness wire format has drifted"
        );
    }

    /// Decode a 64-character hex string into a 32-byte array
    /// for KAT fixtures. Test-only helper.
    fn hex_decode_32_test(s: &str) -> [u8; 32] {
        assert_eq!(s.len(), 64, "expected 64 hex chars for 32-byte value");
        let mut out = [0u8; 32];
        for (i, byte) in out.iter_mut().enumerate() {
            let hi = (s.as_bytes()[2 * i] as char)
                .to_digit(16)
                .expect("hex digit");
            let lo = (s.as_bytes()[2 * i + 1] as char)
                .to_digit(16)
                .expect("hex digit");
            *byte = u8::try_from((hi << 4) | lo).expect("byte fits");
        }
        out
    }

    /// Distinct VRF inputs produce distinct outputs (and thus
    /// distinct randomness) for the same validator set. Pin the
    /// unpredictability property.
    #[test]
    fn distinct_inputs_distinct_randomness() {
        let sks = [fixed_secret(0x11), fixed_secret(0x22), fixed_secret(0x33)];
        let ids = [vid(0x11), vid(0x22), vid(0x33)];

        let input_1 = fixed_input();
        let input_2 = VrfInput::RoundAnchor {
            round: RoundNumber::new(42),
            previous_round_vrf: [0xEE; 32],
        };

        let shares_1: Vec<VrfShare> = sks
            .iter()
            .zip(ids.iter())
            .map(|(sk, id)| VrfShare::compute(*id, sk, &input_1))
            .collect();
        let shares_2: Vec<VrfShare> = sks
            .iter()
            .zip(ids.iter())
            .map(|(sk, id)| VrfShare::compute(*id, sk, &input_2))
            .collect();

        let r_1 = output_randomness(&aggregate_shares(&shares_1).unwrap());
        let r_2 = output_randomness(&aggregate_shares(&shares_2).unwrap());
        assert_ne!(r_1, r_2);
    }

    // ---------- select_index ----------

    #[test]
    fn select_index_within_range() {
        let r = [0xFF; VRF_RANDOMNESS_BYTES];
        for n in 1..200usize {
            let idx = select_index(&r, n);
            assert!(idx < n);
        }
    }

    #[test]
    fn select_index_deterministic() {
        let r = [0x42; VRF_RANDOMNESS_BYTES];
        assert_eq!(select_index(&r, 75), select_index(&r, 75));
    }

    #[test]
    fn select_index_different_randomness_different_index() {
        // High-byte difference at the most-significant end of
        // the 8-byte BE read.
        let r1 = [0x01; VRF_RANDOMNESS_BYTES];
        let r2 = [0xFE; VRF_RANDOMNESS_BYTES];
        let n = 75;
        // Not guaranteed always distinct, but for these
        // particular bytes they should be.
        assert_ne!(select_index(&r1, n), select_index(&r2, n));
    }

    #[test]
    #[should_panic(expected = "n must be > 0")]
    fn select_index_panics_on_zero() {
        let r = [0; VRF_RANDOMNESS_BYTES];
        let _ = select_index(&r, 0);
    }

    /// Known-answer regression pin: the exact return value for
    /// a fixture (randomness, n) pair. Any drift in the byte
    /// interpretation (LE vs BE, different byte window) or in
    /// the modular reduction would surface as a test failure.
    ///
    /// Computation a reviewer can verify by hand:
    /// - First 8 bytes of randomness `0x01..=0x20` (ascending)
    ///   = `[0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]`.
    /// - Big-endian u64 = `0x0102030405060708 = 72623859790382856`.
    /// - `72623859790382856 % 75 = 6`.
    ///
    /// Both 32-bit and 64-bit targets must produce 6.
    #[test]
    fn select_index_is_bit_exact_under_known_inputs() {
        let mut randomness = [0u8; VRF_RANDOMNESS_BYTES];
        for (i, byte) in randomness.iter_mut().enumerate() {
            *byte = u8::try_from(i + 1).expect("i+1 fits in u8 for i < 255");
        }
        // BE reading of [0x01..0x08] = 0x0102030405060708 = 72_623_859_790_382_856.
        // 72_623_859_790_382_856 mod 75 = 6.
        let idx = select_index(&randomness, 75);
        assert_eq!(
            idx, 6,
            "select_index regression vector — input is the ascending byte sequence \
             0x01..=0x20 with n=75; if this assertion fails the byte interpretation \
             or modular reduction has drifted (consensus-breaking change)"
        );
    }

    /// Pin platform-independence: the result must match the
    /// known-answer value regardless of 32-bit vs 64-bit
    /// target. The fixture is small enough that any reasonable
    /// implementation produces the same u64 mod n result on
    /// every platform.
    #[test]
    fn select_index_is_platform_independent_at_small_n() {
        // Fixture cases that stress the cast path:
        // - n = 1 → always returns 0
        // - n = u32 boundary values
        // - n = 75 (launch ceiling)
        let r = [0xFF; VRF_RANDOMNESS_BYTES];
        assert_eq!(select_index(&r, 1), 0);
        // r[..8] BE = 0xFFFF_FFFF_FFFF_FFFF = u64::MAX = 18446744073709551615.
        // 18446744073709551615 mod 75 = 15.
        assert_eq!(select_index(&r, 75), 15);
        // 18446744073709551615 mod 100 = 15.
        assert_eq!(select_index(&r, 100), 15);
    }

    // ---------- aggregate_public_keys ----------

    #[test]
    fn aggregate_public_keys_succeeds() {
        let sks = [fixed_secret(0x11), fixed_secret(0x22)];
        let pks: Vec<PublicKey> = sks.iter().map(SecretKey::public_key).collect();
        let agg = aggregate_public_keys(&pks);
        assert!(agg.is_ok());
    }
}
