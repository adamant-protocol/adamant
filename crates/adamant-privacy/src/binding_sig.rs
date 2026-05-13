#![allow(
    clippy::doc_markdown,
    clippy::cloned_ref_to_slice_refs,
    clippy::missing_panics_doc,
    clippy::needless_pass_by_value,
    clippy::similar_names,
    reason = "doc_markdown: Schnorr math notation (R_commit, bsk, bvk) reads more \
              clearly without inline-code wrapping. cloned_ref_to_slice_refs: tests \
              build single-element slices that need cloned ownership for the next \
              iteration's `.verifying_key()` call. missing_panics_doc: internal \
              `.try_into().expect(...)` calls operate on slices of compile-time- \
              known length where the panic is structurally unreachable. \
              similar_names: cryptographic-fixture variables (bsk_a/bsk_b, r_in_a/r_in_b) \
              follow the math conventions of the protocol spec."
)]

//! Value-commitment binding signature per whitepaper §7.3.1.2
//! (post-amendment instance 33).
//!
//! Pre-Phase-10 audit closure — Privacy H-4 remediation. The
//! binding signature ties a shielded transaction's input/output
//! value commitments to the validity proof and provides
//! cryptographic attestation that the homomorphic balance
//! equation holds. Without this signature wired through to
//! verification, the §7.3.2 statement 4 balance attestation is
//! structurally unenforceable on-chain.
//!
//! # Spec basis
//!
//! Per §7.3.1.2:
//!
//! > The binding signature commits to the randomness sum
//! > `r_balance = Σ r_in - Σ r_out` of the value commitments.
//! > Verification: validators compute the left-hand side of
//! > the balance equation
//! >
//! > `bvk = Σ vc_in - Σ vc_out - Σ_τ (fee_τ · V_τ)`
//! >
//! > and verify the binding signature against `bvk` interpreted
//! > as `r_balance · R` for some hidden `r_balance`. The
//! > signature attests the prover knows that `r_balance`.
//!
//! # Construction
//!
//! Standard Schnorr signature over Pallas with `R` (the value-
//! commitment randomness generator from §7.3.1.2) as the base
//! point.
//!
//! - **Signing key** `bsk` = `Σ r_in - Σ r_out` (Pallas scalar).
//! - **Verifying key** `bvk` = `bsk · R` (Pallas point) — equals
//!   `balance_lhs(...)` if and only if values balance and the
//!   prover knows the per-commitment randomness.
//! - **Sign(bsk, sighash)**:
//!   1. Derive deterministic nonce `r = HashToScalar(NONCE_TAG, bsk || sighash, 64)`.
//!   2. Compute commitment point `R_commit = r · R`.
//!   3. Compute challenge `c = HashToScalar(CHALLENGE_TAG, R_commit || bvk || sighash, 64)`.
//!   4. Compute response `s = r + c · bsk`.
//!   5. Output signature `(R_commit_bytes || s_bytes)` = 64 bytes.
//! - **Verify(bvk, sighash, signature)**:
//!   1. Parse `R_commit`, `s` from the signature bytes.
//!   2. Recompute `c = HashToScalar(CHALLENGE_TAG, R_commit || bvk || sighash, 64)`.
//!   3. Check `s · R == R_commit + c · bvk`.
//!
//! # SIGHASH derivation
//!
//! The SIGHASH binds the binding signature to the transaction
//! context. Computed via [`compute_sighash`] as
//! `sha3_256_tagged(BINDING_SIGHASH, BCS(sighash_inputs))` where
//! `sighash_inputs` carries the input + output commitment lists
//! and the public fee schedule. Different transactions produce
//! different sighashes; an attacker cannot reuse a binding
//! signature across transactions.

use std::convert::TryInto;

use adamant_crypto::domain::{self, DomainTag};
use adamant_crypto::hash::{sha3_256_tagged, shake_256_tagged};
use pasta_curves::group::ff::{Field, FromUniformBytes, PrimeField};
use pasta_curves::group::{Curve, GroupEncoding};
use pasta_curves::pallas;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;
use zeroize::Zeroize;

use crate::stealth::SCALAR_BYTES;
use crate::value_commitment::{
    self, randomness_generator, ValueCommitment, ValueCommitmentRandomness,
};

/// Byte length of a [`ValueBindingSignature`] (`R_commit` + `s`).
pub const VALUE_BINDING_SIGNATURE_BYTES: usize = 64;

/// Byte length of a [`ValueBindingVerifyingKey`] (canonical
/// compressed Pallas point).
pub const VALUE_BINDING_VERIFYING_KEY_BYTES: usize = 32;

// Domain tags for nonce + challenge derivation live in
// `adamant_crypto::domain` per §3.3.1 — `BINDING_NONCE` and
// `BINDING_CHALLENGE`. Registered there alongside the
// consensus-binding `BINDING_SIGHASH` tag.

// ---------------------------------------------------------------
// Signing key (secret scalar)
// ---------------------------------------------------------------

/// Schnorr signing key for the §7.3.1.2 binding signature.
///
/// Wraps a Pallas scalar `bsk = Σ r_in - Σ r_out`. Held secret
/// by the shielded-transaction sender; never appears on-chain.
/// Drop-time zeroization replaces the inner scalar with
/// `Fq::ZERO` per the
/// [`crate::stealth::SpendingPrivateKey`] posture.
#[derive(Clone, Debug)]
pub struct ValueBindingSigningKey(pallas::Scalar);

impl ValueBindingSigningKey {
    /// Derive the signing key from the per-commitment
    /// randomness scalars: `bsk = Σ r_in - Σ r_out`.
    ///
    /// The sender holds the `r_in` randomness for spent notes
    /// (received via the previous transaction's encrypted
    /// memo) and freshly samples the `r_out` randomness for
    /// outputs being created. Both sides are required to
    /// derive the signing key.
    #[must_use]
    pub fn from_randomness(
        input_randomness: &[ValueCommitmentRandomness],
        output_randomness: &[ValueCommitmentRandomness],
    ) -> Self {
        let mut bsk = pallas::Scalar::ZERO;
        for r in input_randomness {
            // Explicit dereference: `r` is `&ValueCommitmentRandomness`,
            // `r.as_scalar()` returns `&pallas::Scalar`. Dereferencing
            // to a value-type Scalar is required for the += operator
            // to do scalar-field arithmetic (pasta_curves's
            // `AddAssign<&Scalar>` impl appears to be missing or
            // mis-defined on the workspace pin; explicit deref
            // sidesteps any ambiguity).
            bsk += *r.as_scalar();
        }
        for r in output_randomness {
            bsk -= *r.as_scalar();
        }
        Self(bsk)
    }

    /// Derive the verifying key `bvk = bsk · R` from this
    /// signing key. The verifying key must equal
    /// [`value_commitment::balance_lhs`]'s output when the
    /// transaction balances; this is what makes the signature
    /// a value-balance attestation.
    #[must_use]
    pub fn verifying_key(&self) -> ValueBindingVerifyingKey {
        let r_gen = randomness_generator();
        let bvk_point = r_gen * self.0;
        ValueBindingVerifyingKey(bvk_point.to_affine())
    }

    /// Schnorr-sign the supplied 32-byte `sighash` under this
    /// signing key per the §7.3.1.2 construction.
    ///
    /// Deterministic per [RFC 6979]-style: the nonce is derived
    /// from `Hash(NONCE || bsk || sighash)` so repeated signing
    /// of the same input produces the same signature. This
    /// removes the standard Schnorr-nonce-reuse footgun without
    /// requiring an external CSPRNG.
    ///
    /// [RFC 6979]: https://datatracker.ietf.org/doc/html/rfc6979
    #[must_use]
    pub fn sign(&self, sighash: &[u8; 32]) -> ValueBindingSignature {
        // Derive deterministic nonce r per RFC-6979 shape.
        let mut nonce_input = Vec::with_capacity(SCALAR_BYTES + 32);
        nonce_input.extend_from_slice(&self.0.to_repr());
        nonce_input.extend_from_slice(sighash);
        let nonce_bytes = shake_64(&domain::BINDING_NONCE, &nonce_input);
        let r = pallas::Scalar::from_uniform_bytes(&nonce_bytes);

        // Commitment point R_commit = r · R.
        let r_gen = randomness_generator();
        let r_commit_point = r_gen * r;
        let r_commit_affine = r_commit_point.to_affine();
        let r_commit_bytes = r_commit_affine.to_bytes();

        // Challenge c = Hash(R_commit || bvk || sighash).
        let bvk = self.verifying_key();
        let c = compute_challenge(&r_commit_bytes, &bvk.to_bytes(), sighash);

        // Response s = r + c · bsk.
        let s = r + c * self.0;

        // Serialise (R_commit, s) as 64 bytes.
        let mut sig_bytes = [0u8; VALUE_BINDING_SIGNATURE_BYTES];
        sig_bytes[..32].copy_from_slice(&r_commit_bytes);
        sig_bytes[32..].copy_from_slice(&s.to_repr());
        ValueBindingSignature(sig_bytes)
    }
}

impl Drop for ValueBindingSigningKey {
    fn drop(&mut self) {
        self.0 = pallas::Scalar::ZERO;
    }
}

impl Zeroize for ValueBindingSigningKey {
    fn zeroize(&mut self) {
        self.0 = pallas::Scalar::ZERO;
    }
}

// ---------------------------------------------------------------
// Verifying key (public point)
// ---------------------------------------------------------------

/// Schnorr verifying key for the §7.3.1.2 binding signature.
///
/// Wraps a Pallas affine point `bvk = bsk · R`. Publicly
/// derivable from the homomorphic value-commitment sum via
/// [`balance_lhs`]; the binding signature's correctness is
/// the proof that the prover knows the secret `bsk`.
///
/// [`balance_lhs`]: crate::value_commitment::balance_lhs
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ValueBindingVerifyingKey(pallas::Affine);

impl ValueBindingVerifyingKey {
    /// Construct from the homomorphic balance-equation
    /// left-hand-side Pallas point. Pass the output of
    /// [`balance_lhs`] (which the verifier computes from the
    /// public input/output value commitments + public fee
    /// amounts) to obtain the verifying key.
    ///
    /// [`balance_lhs`]: crate::value_commitment::balance_lhs
    #[must_use]
    pub fn from_balance_point(point: pallas::Point) -> Self {
        Self(point.to_affine())
    }

    /// Compute the verifying key directly from a transaction's
    /// public commitment data. Convenience wrapper around
    /// `balance_lhs` + `from_balance_point`.
    ///
    /// # Errors
    ///
    /// Returns [`value_commitment::BalanceError`] if any
    /// commitment fails to decode as a Pallas point.
    pub fn from_transaction_data(
        input_commitments: &[ValueCommitment],
        output_commitments: &[ValueCommitment],
        fees: &[value_commitment::FeeEntry],
    ) -> Result<Self, value_commitment::BalanceError> {
        let lhs = value_commitment::balance_lhs(input_commitments, output_commitments, fees)?;
        Ok(Self::from_balance_point(lhs))
    }

    /// Construct from canonical 32-byte compressed encoding.
    /// Returns `None` if the bytes don't decode as a valid
    /// Pallas point.
    #[must_use]
    pub fn from_bytes(bytes: &[u8; VALUE_BINDING_VERIFYING_KEY_BYTES]) -> Option<Self> {
        let opt = pallas::Affine::from_bytes(bytes);
        if bool::from(opt.is_some()) {
            Some(Self(opt.expect(
                "Adamant invariant: is_some() returned true on the previous line",
            )))
        } else {
            None
        }
    }

    /// Canonical 32-byte compressed-point encoding.
    #[must_use]
    pub fn to_bytes(&self) -> [u8; VALUE_BINDING_VERIFYING_KEY_BYTES] {
        self.0.to_bytes()
    }
}

// ---------------------------------------------------------------
// Signature
// ---------------------------------------------------------------

/// 64-byte Schnorr signature for the §7.3.1.2 binding-signature
/// scheme. Wire format: `R_commit_bytes (32) || s_bytes (32)`.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ValueBindingSignature(#[serde(with = "BigArray")] [u8; VALUE_BINDING_SIGNATURE_BYTES]);

impl ValueBindingSignature {
    /// Construct from raw 64-byte material (no validation).
    #[must_use]
    pub const fn from_bytes(bytes: [u8; VALUE_BINDING_SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 64-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; VALUE_BINDING_SIGNATURE_BYTES] {
        self.0
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VALUE_BINDING_SIGNATURE_BYTES] {
        &self.0
    }

    /// Verify this signature against the supplied verifying
    /// key and SIGHASH per the §7.3.1.2 Schnorr equation:
    /// `s · R == R_commit + c · bvk`.
    ///
    /// Returns `true` iff the signature is structurally valid
    /// and the Schnorr equation holds. Constant-time discipline:
    /// returns `false` rather than detail-rich errors on
    /// rejection, matching the discipline of every other
    /// cryptographic verify path in the protocol.
    #[must_use]
    pub fn verify(&self, vk: &ValueBindingVerifyingKey, sighash: &[u8; 32]) -> bool {
        // Parse R_commit + s out of the signature bytes.
        let r_commit_bytes: [u8; 32] = self.0[..32].try_into().expect("32 bytes by slice");
        let s_bytes: [u8; SCALAR_BYTES] = self.0[32..].try_into().expect("32 bytes by slice");
        let r_commit_opt = pallas::Affine::from_bytes(&r_commit_bytes);
        if bool::from(r_commit_opt.is_none()) {
            return false;
        }
        let r_commit = r_commit_opt.expect("Adamant invariant: is_some checked above");
        let s_opt = pallas::Scalar::from_repr(s_bytes);
        if bool::from(s_opt.is_none()) {
            return false;
        }
        let s = s_opt.expect("Adamant invariant: is_some checked above");

        // Recompute challenge c.
        let c = compute_challenge(&r_commit_bytes, &vk.to_bytes(), sighash);

        // Verify: s · R == R_commit + c · bvk.
        let r_gen = randomness_generator();
        let lhs = r_gen * s;
        let bvk_point = pallas::Point::from(vk.0);
        let r_commit_point = pallas::Point::from(r_commit);
        let rhs = r_commit_point + bvk_point * c;
        lhs == rhs
    }
}

// ---------------------------------------------------------------
// SIGHASH derivation
// ---------------------------------------------------------------

/// BCS-serializable input shape for [`compute_sighash`]. The
/// SIGHASH binds the binding signature to the transaction's
/// public commitment data + fee schedule.
#[derive(Debug, Serialize)]
struct SighashInputs<'a> {
    input_commitments: &'a [ValueCommitment],
    output_commitments: &'a [ValueCommitment],
    fees: &'a [value_commitment::FeeEntry],
}

/// Compute the canonical 32-byte SIGHASH the binding signature
/// commits to.
///
/// `sighash = sha3_256_tagged(BINDING_SIGHASH, BCS(SighashInputs))`.
///
/// Per the Crypto H-4 remediation, the SIGHASH binds the
/// binding signature to:
///
/// - the ordered list of input value commitments,
/// - the ordered list of output value commitments,
/// - the public fee schedule.
///
/// Different transactions produce different SIGHASHes; an
/// attacker cannot transplant a binding signature from one
/// transaction to another.
///
/// # Panics
///
/// Cannot panic in practice. The internal `expect` is a
/// contract assertion: BCS serialisation of fixed-shape
/// types is infallible.
#[must_use]
pub fn compute_sighash(
    input_commitments: &[ValueCommitment],
    output_commitments: &[ValueCommitment],
    fees: &[value_commitment::FeeEntry],
) -> [u8; 32] {
    let inputs = SighashInputs {
        input_commitments,
        output_commitments,
        fees,
    };
    let bcs_bytes = bcs::to_bytes(&inputs)
        .expect("Adamant invariant: SighashInputs is BCS-serialisable by construction");
    sha3_256_tagged(&domain::BINDING_SIGHASH, &bcs_bytes)
}

// ---------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------

/// Compute the Schnorr challenge `c = HashToScalar(R_commit || bvk || sighash)`.
fn compute_challenge(
    r_commit_bytes: &[u8; 32],
    bvk_bytes: &[u8; VALUE_BINDING_VERIFYING_KEY_BYTES],
    sighash: &[u8; 32],
) -> pallas::Scalar {
    let mut input = Vec::with_capacity(32 + VALUE_BINDING_VERIFYING_KEY_BYTES + 32);
    input.extend_from_slice(r_commit_bytes);
    input.extend_from_slice(bvk_bytes);
    input.extend_from_slice(sighash);
    let bytes = shake_64(&domain::BINDING_CHALLENGE, &input);
    pallas::Scalar::from_uniform_bytes(&bytes)
}

/// SHAKE-256 with a domain-tag wrapping, producing 64 uniform
/// bytes for Pallas-scalar reduction via
/// `from_uniform_bytes`. Thin wrapper over
/// `adamant_crypto::hash::shake_256_tagged`.
fn shake_64(tag: &DomainTag, input: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    shake_256_tagged(tag, input, &mut out);
    out
}

// ---------------------------------------------------------------
// Tests
// ---------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_types::TypeId;

    /// Test-only randomness fixture. Builds 64 uniform bytes
    /// from the seed via two SHAKE-256-tagged calls so that
    /// distinct seeds produce scalars that are NOT linearly
    /// related. Avoids the `[seed; 64]` trap:
    /// `[s; 64]` interpreted as an integer equals
    /// `s · 0x01010...01` so `scalar(1) - scalar(2) ==
    /// scalar(3) - scalar(4)` and the signing-key derivation
    /// `Σ r_in - Σ r_out` collides under linearly-spaced
    /// seeds.
    fn fixed_randomness(seed: u8) -> ValueCommitmentRandomness {
        use adamant_crypto::domain::OBJECT_ID;
        use adamant_crypto::hash::shake_256_tagged;
        let mut out = [0u8; 64];
        // OBJECT_ID is just a stable registered tag we
        // borrow at test time; any registered tag works since
        // this is fixture-only domain separation.
        shake_256_tagged(&OBJECT_ID, &[seed], &mut out);
        ValueCommitmentRandomness::from_uniform_bytes(&out)
    }

    fn type_id(byte: u8) -> TypeId {
        TypeId::from_bytes([byte; 32])
    }

    // ---------- Sign/verify round-trip ----------

    /// Sign-then-verify under matching key + SIGHASH succeeds.
    /// The headline H-4 fix: a binding signature now has a
    /// verify surface that callers can invoke.
    #[test]
    fn sign_then_verify_round_trip() {
        let r_in = fixed_randomness(0x01);
        let r_out = fixed_randomness(0x02);
        let bsk = ValueBindingSigningKey::from_randomness(&[r_in.clone()], &[r_out.clone()]);
        let bvk = bsk.verifying_key();
        let sighash = [0xAB; 32];
        let sig = bsk.sign(&sighash);
        assert!(sig.verify(&bvk, &sighash), "honest signature must verify");
    }

    /// Verify fails under a different SIGHASH (the canonical
    /// transaction-replay attack: lifting a binding signature
    /// from one transaction to another).
    #[test]
    fn verify_rejects_different_sighash() {
        let r_in = fixed_randomness(0x01);
        let r_out = fixed_randomness(0x02);
        let bsk = ValueBindingSigningKey::from_randomness(&[r_in], &[r_out]);
        let bvk = bsk.verifying_key();
        let sig = bsk.sign(&[0xAB; 32]);
        // Different SIGHASH — replay attempt.
        assert!(!sig.verify(&bvk, &[0xCD; 32]));
    }

    /// Verify fails under a different verifying key (the
    /// rogue-balance attack: attacker swapping commitments to
    /// change the homomorphic sum without resigning).
    #[test]
    fn verify_rejects_different_verifying_key() {
        let r_in_a = fixed_randomness(0x01);
        let r_out_a = fixed_randomness(0x02);
        let bsk_a = ValueBindingSigningKey::from_randomness(&[r_in_a], &[r_out_a]);
        let bvk_a = bsk_a.verifying_key();
        let sig = bsk_a.sign(&[0xAB; 32]);

        // Different signing key → different verifying key.
        let r_in_b = fixed_randomness(0x03);
        let r_out_b = fixed_randomness(0x04);
        let bsk_b = ValueBindingSigningKey::from_randomness(&[r_in_b], &[r_out_b]);
        let bvk_b = bsk_b.verifying_key();
        // Sanity check that bvk_a != bvk_b.
        assert_ne!(bvk_a, bvk_b, "test fixture invariant: bvk_a != bvk_b");
        assert!(!sig.verify(&bvk_b, &[0xAB; 32]));
    }

    /// Verify rejects a tampered signature (any bit flip in
    /// R_commit or s).
    #[test]
    fn verify_rejects_tampered_signature() {
        let r_in = fixed_randomness(0x01);
        let r_out = fixed_randomness(0x02);
        let bsk = ValueBindingSigningKey::from_randomness(&[r_in], &[r_out]);
        let bvk = bsk.verifying_key();
        let sighash = [0xAB; 32];
        let mut sig = bsk.sign(&sighash);
        // Flip a bit in the s component (last 32 bytes).
        let bytes = sig.as_bytes();
        let mut tampered = *bytes;
        tampered[35] ^= 0x01;
        sig = ValueBindingSignature::from_bytes(tampered);
        assert!(!sig.verify(&bvk, &sighash));
    }

    /// Determinism: signing the same SIGHASH twice with the
    /// same signing key produces the same signature. This is
    /// the RFC-6979-style nonce-derivation property; removes
    /// the nonce-reuse footgun for callers.
    #[test]
    fn sign_is_deterministic() {
        let r_in = fixed_randomness(0x01);
        let r_out = fixed_randomness(0x02);
        let bsk = ValueBindingSigningKey::from_randomness(&[r_in], &[r_out]);
        let sighash = [0xAB; 32];
        let sig1 = bsk.sign(&sighash);
        let sig2 = bsk.sign(&sighash);
        assert_eq!(sig1, sig2);
    }

    // ---------- Verifying-key construction ----------

    /// `from_transaction_data` produces the same verifying key
    /// as `bsk.verifying_key()` when values balance. This is
    /// the headline H-4 property: the on-chain public-data
    /// balance computation matches the prover's secret-data
    /// signing-key derivation.
    #[test]
    fn verifying_key_matches_balance_lhs_when_balanced() {
        let asset = type_id(1);
        let r_in = fixed_randomness(0x11);
        let r_out = fixed_randomness(0x11); // same r so bsk = 0
        let vc_in = value_commitment::commit(100, asset, &r_in);
        let vc_out = value_commitment::commit(100, asset, &r_out);
        // bsk = r_in - r_out = 0 → bvk = identity.
        let bsk = ValueBindingSigningKey::from_randomness(&[r_in.clone()], &[r_out.clone()]);
        let bvk_from_key = bsk.verifying_key();
        // Recompute bvk from chain-public data via balance_lhs.
        let bvk_from_balance =
            ValueBindingVerifyingKey::from_transaction_data(&[vc_in], &[vc_out], &[])
                .expect("balance_lhs");
        assert_eq!(bvk_from_key, bvk_from_balance);
    }

    /// When values balance but randomness differs, the
    /// verifying key is NOT the identity — but signing/verify
    /// still works.
    #[test]
    fn verifying_key_works_for_unequal_randomness() {
        let asset = type_id(1);
        let r_in = fixed_randomness(0x11);
        let r_out = fixed_randomness(0x22);
        let vc_in = value_commitment::commit(100, asset, &r_in);
        let vc_out = value_commitment::commit(100, asset, &r_out);
        let bsk = ValueBindingSigningKey::from_randomness(&[r_in.clone()], &[r_out.clone()]);
        let bvk_from_key = bsk.verifying_key();
        let bvk_from_balance =
            ValueBindingVerifyingKey::from_transaction_data(&[vc_in], &[vc_out], &[])
                .expect("balance_lhs");
        assert_eq!(bvk_from_key, bvk_from_balance);
        // Round-trip sign-verify under the balance-derived vk.
        let sighash = [0xFE; 32];
        let sig = bsk.sign(&sighash);
        assert!(sig.verify(&bvk_from_balance, &sighash));
    }

    // ---------- SIGHASH determinism + binding ----------

    #[test]
    fn sighash_is_deterministic() {
        let asset = type_id(1);
        let r = fixed_randomness(0x11);
        let vc = value_commitment::commit(100, asset, &r);
        let s1 = compute_sighash(&[vc], &[vc], &[]);
        let s2 = compute_sighash(&[vc], &[vc], &[]);
        assert_eq!(s1, s2);
    }

    #[test]
    fn sighash_distinguishes_different_transactions() {
        let asset = type_id(1);
        let r = fixed_randomness(0x11);
        let vc_a = value_commitment::commit(100, asset, &r);
        let vc_b = value_commitment::commit(200, asset, &r);
        let s_a = compute_sighash(&[vc_a], &[vc_a], &[]);
        let s_b = compute_sighash(&[vc_b], &[vc_b], &[]);
        assert_ne!(s_a, s_b);
    }

    // ---------- Byte round-trips ----------

    #[test]
    fn signature_byte_round_trip() {
        let bsk = ValueBindingSigningKey::from_randomness(
            &[fixed_randomness(0x01)],
            &[fixed_randomness(0x02)],
        );
        let sig = bsk.sign(&[0xAB; 32]);
        let bytes = sig.to_bytes();
        let decoded = ValueBindingSignature::from_bytes(bytes);
        assert_eq!(sig, decoded);
        assert_eq!(bytes.len(), VALUE_BINDING_SIGNATURE_BYTES);
    }

    #[test]
    fn signature_bcs_round_trip() {
        let bsk = ValueBindingSigningKey::from_randomness(
            &[fixed_randomness(0x01)],
            &[fixed_randomness(0x02)],
        );
        let sig = bsk.sign(&[0xAB; 32]);
        let bcs_bytes = bcs::to_bytes(&sig).expect("encode");
        let decoded: ValueBindingSignature = bcs::from_bytes(&bcs_bytes).expect("decode");
        assert_eq!(sig, decoded);
    }

    #[test]
    fn verifying_key_byte_round_trip() {
        let bsk = ValueBindingSigningKey::from_randomness(
            &[fixed_randomness(0x01)],
            &[fixed_randomness(0x02)],
        );
        let bvk = bsk.verifying_key();
        let bytes = bvk.to_bytes();
        let decoded = ValueBindingVerifyingKey::from_bytes(&bytes).expect("decode");
        assert_eq!(bvk, decoded);
    }
}
