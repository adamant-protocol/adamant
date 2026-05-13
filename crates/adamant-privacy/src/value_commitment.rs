//! Pedersen value commitments per whitepaper §7.3.1.2 (post-
//! amendment instance 33).
//!
//! Phase 6.8b.4d-2.a — out-of-circuit value-commitment surface.
//! Wallet code constructs a [`ValueCommitment`] by sampling
//! randomness and combining it with the value + asset-type
//! generators on Pallas. The chain-level balance check
//! ([`balance_lhs`]) operates on collections of commitments
//! and explicit fees and produces the Pallas point that the
//! binding signature must commit to.
//!
//! # Spec basis
//!
//! Whitepaper §7.3.1.2 verbatim:
//!
//! > A `ValueCommitment` is a 32-byte Pedersen-style commitment
//! > on the Pallas curve that hides a note's value while
//! > remaining additively homomorphic.
//! >
//! > ```text
//! > vc = v · V_τ + r · R   (a Pallas point)
//! > V_τ = HashToCurve("ADAMANT-v1-vc-base", τ_bytes)
//! > R   = HashToCurve("ADAMANT-v1-vc-randomness", b"")
//! > ```
//! >
//! > The on-chain encoding of `vc` is the 32-byte canonical
//! > compressed Pallas point form (x-coordinate plus 1-bit
//! > y-sign per pasta_curves' `GroupEncoding`).
//!
//! # Construction (off-circuit)
//!
//! - `V_τ` derived once per asset type via
//!   [`asset_value_generator`] using
//!   `pasta_curves::pallas::Point::hash_to_curve` with the
//!   `b"ADAMANT-v1-vc-base"` domain prefix and the 32-byte
//!   canonical asset-type encoding as the message input.
//! - `R` derived once at startup via [`randomness_generator`]
//!   using `Point::hash_to_curve` with the
//!   `b"ADAMANT-v1-vc-randomness"` domain prefix and an empty
//!   message. `R` is deterministically the same Pallas point
//!   for every protocol participant.
//! - The commitment uses Pallas point arithmetic (point
//!   addition + scalar multiplication via the
//!   `pasta_curves::pallas` Group/Field traits).
//!
//! # In-circuit / out-of-circuit boundary
//!
//! The validity circuit (Phase 6.8b.4d-2.c) attests per-
//! commitment opening knowledge: given witness `(v, τ, r)`,
//! the prover proves `vc = v · V_τ + r · R` in-circuit using
//! the ECC chips forked at Phase 6.8b.3. The chain-level
//! homomorphic balance check ([`balance_lhs`] off-circuit) is
//! evaluated by validators on public data — no proof needed
//! for the balance equation itself, only for the per-commitment
//! opening attestation.
//!
//! # Domain-tag registry
//!
//! Per §3.3.1, both `VALUE_COMMITMENT_BASE` and
//! `VALUE_COMMITMENT_RANDOMNESS` byte tags are consensus-rule
//! constants registered in `adamant-crypto::domain`. Changing
//! them is a hard fork.

use std::sync::OnceLock;

use adamant_crypto::domain;
use adamant_types::TypeId;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::group::ff::FromUniformBytes;
use pasta_curves::group::{Curve, Group, GroupEncoding};
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::Zeroize;

use crate::stealth::SCALAR_BYTES;

/// Byte length of an on-chain `ValueCommitment` per whitepaper
/// §7.3.1.2: the Pallas-affine compressed-point encoding
/// (x-coordinate plus 1-bit y-sign in the high bit of byte 31).
pub const VALUE_COMMITMENT_BYTES: usize = 32;

/// On-chain Pedersen value commitment per whitepaper §7.3.1.2.
///
/// Wraps a Pallas affine point in its 32-byte canonical
/// compressed encoding. The point itself is recoverable via
/// [`ValueCommitment::to_point`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValueCommitment(#[serde(with = "BigArray")] [u8; VALUE_COMMITMENT_BYTES]);

impl ValueCommitment {
    /// Construct from raw 32-byte material (e.g., loading from
    /// on-chain serialized form). Does NOT validate that the
    /// bytes encode a curve point; use
    /// [`ValueCommitment::to_point`] to recover the point.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; VALUE_COMMITMENT_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte compressed-point encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; VALUE_COMMITMENT_BYTES] {
        self.0
    }

    /// Borrow the underlying bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VALUE_COMMITMENT_BYTES] {
        &self.0
    }

    /// Recover the underlying Pallas affine point.
    ///
    /// Returns `None` if the bytes do not encode a valid
    /// Pallas point (malformed wire data).
    #[must_use]
    pub fn to_point(&self) -> Option<pallas::Affine> {
        let opt = pallas::Affine::from_bytes(&self.0);
        if bool::from(opt.is_some()) {
            Some(opt.expect("Adamant invariant: is_some() returned true on the previous line"))
        } else {
            None
        }
    }

    /// Construct from a Pallas affine point via canonical
    /// compressed encoding.
    #[must_use]
    pub fn from_point(point: &pallas::Affine) -> Self {
        Self(point.to_bytes())
    }
}

/// Per-commitment randomness scalar `r` for value commitments
/// per whitepaper §7.3.1.2.
///
/// Held secret by the value-commitment owner (the spender for
/// input commitments, the sender for output commitments).
/// Sampled fresh per commitment from a CSPRNG. Compromise
/// affects the commitment's value-hiding property.
///
/// Wraps `pallas::Scalar` (Pallas's scalar field `Fq`).
/// Drop-time zeroization replaces the inner scalar with
/// `Fq::ZERO`, same posture as
/// [`crate::stealth::SpendingPrivateKey`].
#[derive(Clone, Debug)]
pub struct ValueCommitmentRandomness(pallas::Scalar);

impl ValueCommitmentRandomness {
    /// Construct from 64 uniformly-distributed bytes (e.g.,
    /// the output of a CSPRNG, or
    /// `tagged_shake_256(domain, ikm, 64)`). The bytes are
    /// reduced into the Pallas scalar field via
    /// `pallas::Scalar::from_uniform_bytes`.
    #[must_use]
    pub fn from_uniform_bytes(bytes: &[u8; 64]) -> Self {
        Self(pallas::Scalar::from_uniform_bytes(bytes))
    }

    /// Construct from the canonical 32-byte little-endian
    /// scalar encoding. Returns `None` if the bytes encode an
    /// integer ≥ the Pallas scalar field characteristic.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; SCALAR_BYTES]) -> Option<Self> {
        use pasta_curves::group::ff::PrimeField;
        let opt = pallas::Scalar::from_repr(*bytes);
        if bool::from(opt.is_some()) {
            Some(Self(opt.expect(
                "Adamant invariant: is_some() returned true on the previous line",
            )))
        } else {
            None
        }
    }

    /// Canonical 32-byte little-endian scalar encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; SCALAR_BYTES] {
        use pasta_curves::group::ff::PrimeField;
        self.0.to_repr()
    }

    /// Borrow the underlying scalar. Crate-internal — used by
    /// [`commit`] for scalar multiplication.
    pub(crate) const fn as_scalar(&self) -> &pallas::Scalar {
        &self.0
    }
}

impl Drop for ValueCommitmentRandomness {
    fn drop(&mut self) {
        use pasta_curves::group::ff::Field;
        self.0 = pallas::Scalar::ZERO;
    }
}

impl PartialEq for ValueCommitmentRandomness {
    fn eq(&self, other: &Self) -> bool {
        self.0 == other.0
    }
}

impl Eq for ValueCommitmentRandomness {}

impl Zeroize for ValueCommitmentRandomness {
    fn zeroize(&mut self) {
        use pasta_curves::group::ff::Field;
        self.0 = pallas::Scalar::ZERO;
    }
}

// ---------- Generator derivation ----------

/// The universal randomness generator `R` per whitepaper
/// §7.3.1.2. Deterministic across all protocol participants;
/// derived once via `Point::hash_to_curve` with the
/// `VALUE_COMMITMENT_RANDOMNESS` domain tag and an empty
/// message.
///
/// Cached after first call per the §7.3.1.2 implementation
/// note ("Wallet implementations MUST derive `R` lazily once
/// at startup and cache it").
///
/// # Panics
///
/// Cannot panic in practice: the `VALUE_COMMITMENT_RANDOMNESS`
/// byte tag is registered in `adamant-crypto::domain` as
/// `b"ADAMANT-v1-vc-randomness"` — pure ASCII. The
/// `from_utf8` conversion always succeeds for ASCII input.
#[must_use]
pub fn randomness_generator() -> pallas::Point {
    static R: OnceLock<pallas::Point> = OnceLock::new();
    *R.get_or_init(|| {
        let domain_str = core::str::from_utf8(domain::VALUE_COMMITMENT_RANDOMNESS.as_bytes())
            .expect("VALUE_COMMITMENT_RANDOMNESS tag is ASCII");
        let hasher = pallas::Point::hash_to_curve(domain_str);
        hasher(b"")
    })
}

/// The asset-specific value generator `V_τ` per whitepaper
/// §7.3.1.2. Derived per asset type via
/// `Point::hash_to_curve` with the `VALUE_COMMITMENT_BASE`
/// domain tag and the asset type's 32-byte canonical
/// encoding as the message.
///
/// Each asset type produces an independent Pallas point
/// (different message → different output). This independence
/// is what makes the §7.3.2 statement 4 per-asset-type
/// balance check work.
///
/// # Panics
///
/// Cannot panic in practice: the `VALUE_COMMITMENT_BASE` byte
/// tag is `b"ADAMANT-v1-vc-base"` (pure ASCII).
#[must_use]
pub fn asset_value_generator(asset_type: TypeId) -> pallas::Point {
    let domain_str = core::str::from_utf8(domain::VALUE_COMMITMENT_BASE.as_bytes())
        .expect("VALUE_COMMITMENT_BASE tag is ASCII");
    let hasher = pallas::Point::hash_to_curve(domain_str);
    hasher(&asset_type.to_bytes())
}

// ---------- Commit ----------

/// Construct a value commitment per whitepaper §7.3.1.2:
///
/// `vc = v · V_τ + r · R`
///
/// where `V_τ` is asset-type-specific and `R` is the universal
/// randomness generator.
#[must_use]
pub fn commit(
    value: u64,
    asset_type: TypeId,
    randomness: &ValueCommitmentRandomness,
) -> ValueCommitment {
    let v_t = asset_value_generator(asset_type);
    let r_g = randomness_generator();
    let v_scalar = pallas::Scalar::from(value);
    let point = v_t * v_scalar + r_g * randomness.as_scalar();
    ValueCommitment::from_point(&point.to_affine())
}

// ---------- Balance check (chain-level) ----------

/// A single fee entry for the chain-level balance check per
/// whitepaper §7.3.2 statement 4: a public `(asset_type,
/// amount)` pair contributing `amount · V_τ` to the
/// balance left-hand side.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct FeeEntry {
    /// Asset type the fee is paid in.
    pub asset_type: TypeId,
    /// Amount in the asset's smallest unit.
    pub amount: u64,
}

impl FeeEntry {
    /// Construct from components.
    #[must_use]
    pub const fn new(asset_type: TypeId, amount: u64) -> Self {
        Self { asset_type, amount }
    }
}

/// Errors returned by [`balance_lhs`].
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BalanceError {
    /// One of the input or output value commitments did not
    /// decode to a valid Pallas point.
    MalformedCommitment,
}

impl core::fmt::Display for BalanceError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("malformed value commitment in balance check")
    }
}

impl std::error::Error for BalanceError {}

/// Compute the left-hand side of the §7.3.2 statement 4
/// balance equation:
///
/// `Σ vc_in − Σ vc_out − Σ_τ (fee_τ · V_τ)`
///
/// At balance (the proof verifies + the binding signature
/// verifies), this point equals `r_balance · R` for some
/// scalar `r_balance` that the binding signature commits to.
///
/// This function is the **chain-level public-data balance
/// computation**: it operates on the wire-form
/// `ShieldedTransaction` plus its public fees and produces
/// the Pallas point that validators compare against the
/// binding-signature key. No zero-knowledge proof is needed
/// for this computation.
///
/// # Errors
///
/// Returns [`BalanceError::MalformedCommitment`] if any input
/// or output commitment fails to decode to a valid Pallas
/// point.
pub fn balance_lhs(
    input_commitments: &[ValueCommitment],
    output_commitments: &[ValueCommitment],
    fees: &[FeeEntry],
) -> Result<pallas::Point, BalanceError> {
    let mut acc = pallas::Point::identity();
    for vc in input_commitments {
        let p = vc.to_point().ok_or(BalanceError::MalformedCommitment)?;
        acc += pallas::Point::from(p);
    }
    for vc in output_commitments {
        let p = vc.to_point().ok_or(BalanceError::MalformedCommitment)?;
        acc -= pallas::Point::from(p);
    }
    for fee in fees {
        let v_t = asset_value_generator(fee.asset_type);
        let amount_scalar = pallas::Scalar::from(fee.amount);
        acc -= v_t * amount_scalar;
    }
    Ok(acc)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn type_id(byte: u8) -> TypeId {
        TypeId::from_bytes([byte; 32])
    }

    fn fixed_randomness(seed: u8) -> ValueCommitmentRandomness {
        ValueCommitmentRandomness::from_uniform_bytes(&[seed; 64])
    }

    // ---------- Generator pins ----------

    #[test]
    fn randomness_generator_is_deterministic() {
        let r1 = randomness_generator();
        let r2 = randomness_generator();
        assert_eq!(r1, r2);
    }

    #[test]
    fn randomness_generator_is_not_identity() {
        assert_ne!(randomness_generator(), pallas::Point::identity());
    }

    #[test]
    fn asset_value_generator_is_deterministic() {
        let asset = type_id(0x42);
        let v1 = asset_value_generator(asset);
        let v2 = asset_value_generator(asset);
        assert_eq!(v1, v2);
    }

    #[test]
    fn asset_value_generators_are_distinct_for_distinct_assets() {
        let v_a = asset_value_generator(type_id(0x01));
        let v_b = asset_value_generator(type_id(0x02));
        assert_ne!(v_a, v_b);
    }

    /// `R` must be independent of every `V_τ` (no known
    /// discrete-log relation). They MUST be different points
    /// — distinct domain prefixes guarantee this in practice.
    #[test]
    fn randomness_generator_differs_from_asset_generators() {
        let r = randomness_generator();
        for byte in [0x00u8, 0x42, 0xFF] {
            assert_ne!(r, asset_value_generator(type_id(byte)));
        }
    }

    // ---------- Commit ----------

    #[test]
    fn commit_is_deterministic() {
        let r = fixed_randomness(0x33);
        let c1 = commit(1000, type_id(0x42), &r);
        let c2 = commit(1000, type_id(0x42), &r);
        assert_eq!(c1, c2);
    }

    #[test]
    fn commit_distinct_values_distinct_commitments() {
        let r = fixed_randomness(0x33);
        let asset = type_id(0x42);
        let c_a = commit(1000, asset, &r);
        let c_b = commit(2000, asset, &r);
        assert_ne!(c_a, c_b);
    }

    #[test]
    fn commit_distinct_assets_distinct_commitments() {
        let r = fixed_randomness(0x33);
        let c_a = commit(1000, type_id(0x01), &r);
        let c_b = commit(1000, type_id(0x02), &r);
        assert_ne!(c_a, c_b);
    }

    #[test]
    fn commit_distinct_randomness_distinct_commitments() {
        let asset = type_id(0x42);
        let c_a = commit(1000, asset, &fixed_randomness(0x33));
        let c_b = commit(1000, asset, &fixed_randomness(0x44));
        assert_ne!(c_a, c_b);
    }

    /// Commit at value=0 produces `r · R`. Useful pin for the
    /// degenerate case.
    #[test]
    fn commit_at_zero_value_equals_r_times_randomness() {
        let r = fixed_randomness(0x33);
        let asset = type_id(0x42);
        let c = commit(0, asset, &r);
        let expected = (randomness_generator() * r.as_scalar()).to_affine();
        assert_eq!(c.to_point().unwrap(), expected);
    }

    // ---------- Balance check ----------

    /// Single input + single output, same asset, same value,
    /// same randomness — sum should be the identity
    /// (`r_balance` = 0).
    #[test]
    fn balance_zeroes_for_matched_input_output() {
        let r = fixed_randomness(0x33);
        let asset = type_id(0x42);
        let v_in = commit(500, asset, &r);
        let v_out = commit(500, asset, &r);
        let lhs = balance_lhs(&[v_in], &[v_out], &[]).unwrap();
        assert_eq!(lhs, pallas::Point::identity());
    }

    /// Single input + single output where input value = output
    /// value + fee. The LHS evaluates to
    /// `(r_in - r_out) · R`. Pin: when
    /// `r_in = r_out`, LHS is identity.
    #[test]
    fn balance_with_fee_balances_when_values_match() {
        let r = fixed_randomness(0x33);
        let asset = type_id(0x42);
        let input_value = 1000u64;
        let output_value = 700u64;
        let fee = 300u64;
        let v_in = commit(input_value, asset, &r);
        let v_out = commit(output_value, asset, &r);
        let lhs = balance_lhs(&[v_in], &[v_out], &[FeeEntry::new(asset, fee)]).unwrap();
        assert_eq!(lhs, pallas::Point::identity());
    }

    /// Negative case: output value + fee != input value. LHS
    /// non-identity, balance fails.
    #[test]
    fn balance_fails_for_inflation_attempt() {
        let r = fixed_randomness(0x33);
        let asset = type_id(0x42);
        // Output 600 + fee 300 = 900, but input is 1000.
        // 100-unit "deflation" — the chain notices.
        let v_in = commit(1000, asset, &r);
        let v_out = commit(600, asset, &r);
        let lhs = balance_lhs(&[v_in], &[v_out], &[FeeEntry::new(asset, 300)]).unwrap();
        assert_ne!(lhs, pallas::Point::identity());
    }

    /// Multi-asset balance: input ADM = output ADM + `fee_ADM`
    /// AND input TOKEN = output TOKEN + `fee_TOKEN`. Both
    /// asset-types balance independently → LHS is identity.
    #[test]
    fn balance_zeroes_for_multi_asset_balanced_tx() {
        let r1 = fixed_randomness(0x11);
        let r2 = fixed_randomness(0x22);
        let r3 = fixed_randomness(0x33);
        let r4 = fixed_randomness(0x44);
        let adm = type_id(0x01);
        let token = type_id(0x02);

        let v_in = vec![commit(1000, adm, &r1), commit(500, token, &r2)];
        let v_out = vec![commit(800, adm, &r3), commit(400, token, &r4)];
        let fees = vec![FeeEntry::new(adm, 200), FeeEntry::new(token, 100)];

        let lhs = balance_lhs(&v_in, &v_out, &fees).unwrap();
        // LHS = (r1 + r2 - r3 - r4) · R + 0_per_asset
        let expected_balance_scalar =
            *r1.as_scalar() + r2.as_scalar() - r3.as_scalar() - r4.as_scalar();
        let expected = randomness_generator() * expected_balance_scalar;
        assert_eq!(lhs, expected);
    }

    /// Multi-asset balance failure: ADM balances but TOKEN
    /// doesn't. LHS contains a nonzero `V_τ` component for
    /// the unbalanced asset type — must NOT equal `r_balance · R`
    /// for any scalar.
    #[test]
    fn balance_fails_when_one_asset_unbalanced_in_multi_asset_tx() {
        let r1 = fixed_randomness(0x11);
        let r2 = fixed_randomness(0x22);
        let r3 = fixed_randomness(0x33);
        let r4 = fixed_randomness(0x44);
        let adm = type_id(0x01);
        let token = type_id(0x02);

        // ADM balances (input 1000 = output 800 + fee 200);
        // TOKEN doesn't (input 500 vs output 400 + fee 50 →
        // 50 short).
        let v_in = vec![commit(1000, adm, &r1), commit(500, token, &r2)];
        let v_out = vec![commit(800, adm, &r3), commit(400, token, &r4)];
        let fees = vec![FeeEntry::new(adm, 200), FeeEntry::new(token, 50)];

        let lhs = balance_lhs(&v_in, &v_out, &fees).unwrap();
        // LHS now contains 50 · V_token + (r1+r2-r3-r4) · R.
        // Even if (r1+r2-r3-r4) · R were zero, the V_token
        // term is nonzero. So LHS != r · R for any scalar r
        // (V_token is independent of R).
        let r_combined = *r1.as_scalar() + r2.as_scalar() - r3.as_scalar() - r4.as_scalar();
        let only_r = randomness_generator() * r_combined;
        assert_ne!(lhs, only_r);
    }

    // ---------- Wire format ----------

    #[test]
    fn value_commitment_round_trips_bytes() {
        let r = fixed_randomness(0x33);
        let asset = type_id(0x42);
        let original = commit(1000, asset, &r);
        let bytes = original.to_bytes();
        let decoded = ValueCommitment::from_bytes(bytes);
        assert_eq!(original, decoded);
    }

    #[test]
    fn value_commitment_to_point_round_trip() {
        let r = fixed_randomness(0x33);
        let asset = type_id(0x42);
        let original = commit(1000, asset, &r);
        let point = original
            .to_point()
            .expect("valid commitment encodes a point");
        let reconstructed = ValueCommitment::from_point(&point);
        assert_eq!(original, reconstructed);
    }

    #[test]
    fn value_commitment_bcs_round_trip() {
        let r = fixed_randomness(0x33);
        let asset = type_id(0x42);
        let original = commit(1000, asset, &r);
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: ValueCommitment = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
        assert_eq!(encoded.len(), VALUE_COMMITMENT_BYTES);
    }

    // ---------- Domain-tag pins ----------

    #[test]
    fn vc_base_tag_is_registry_value() {
        assert_eq!(
            domain::VALUE_COMMITMENT_BASE.as_bytes(),
            b"ADAMANT-v1-vc-base"
        );
    }

    #[test]
    fn vc_randomness_tag_is_registry_value() {
        assert_eq!(
            domain::VALUE_COMMITMENT_RANDOMNESS.as_bytes(),
            b"ADAMANT-v1-vc-randomness"
        );
    }
}
