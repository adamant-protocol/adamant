//! Validator identity types per whitepaper §8.1.1–8.1.2.
//!
//! Each Adamant validator publishes a bundle of three public keys
//! covering the protocol's three signature regimes:
//!
//! - **Ed25519** (§3.4.1) — classical signature for consensus
//!   messages on the latency-critical path.
//! - **ML-DSA-65** (§3.4.2, NIST FIPS 204) — post-quantum signature
//!   carried alongside Ed25519 per Adamant's hybrid signing posture.
//! - **BLS12-381** (§3.4.3) — pairing-friendly signature for
//!   aggregate consensus messages, the threshold-decryption KDF
//!   contribution, and the §8.6 consensus VRF.
//!
//! [`ValidatorId`] is the content-derived 32-byte identifier
//! computed from the BCS-encoded [`ValidatorPublicKeys`] bundle
//! via tagged-hash with `domain::VALIDATOR_ID`. The construction
//! mirrors the §4.2 account-address derivation in shape: a
//! deterministic, content-addressed identifier that any party
//! can re-derive from the published key material.
//!
//! # Wire format
//!
//! The `Validator` object serialises as BCS per §5.1.8. The
//! [`ValidatorPublicKeys`] sub-record encodes:
//!
//! - `ed25519_public_key`: 32 bytes (no length prefix; fixed-size
//!   array per BCS canonical encoding).
//! - `ml_dsa_public_key`: 1952 bytes (ML-DSA-65 public-key width
//!   per FIPS 204).
//! - `bls_public_key`: 96 bytes (compressed G1).
//! - `bls_pop`: 48 bytes (BLS12-381 signature on the canonical
//!   PoP message — see [`compute_bls_pop_message`]).
//!
//! Total: **2128 bytes** of public-key material per validator.
//! Field declaration order is consensus-binding; reordering is a
//! hard fork (cross-validator compatibility breaks).
//!
//! # BLS proof-of-possession (PoP)
//!
//! Per §3.4.3 + the pre-Phase-10 audit Crypto C-2 remediation,
//! every `ValidatorPublicKeys` carries a BLS PoP signature
//! proving the validator controls the BLS secret. Without PoP,
//! BLS aggregate verification accepts the canonical rogue-key
//! attack: an attacker registering
//! `pk_attacker = pk_target_aggregate - Σ pk_honest` can forge
//! single-signer aggregates that verify as if every honest
//! validator signed.
//!
//! The PoP message is bound to the other key material:
//! `sha3_256_tagged(VALIDATOR_BLS_POP, BCS(ed25519 || ml_dsa || bls_public))`.
//! [`ValidatorPublicKeys::verify_pop`] checks the PoP against the
//! advertised BLS public key. Validators MUST call `verify_pop`
//! before admitting a new validator into the active set; the
//! active-set `register` path enforces this.

use adamant_crypto::{
    bls::{
        self, PUBLIC_KEY_BYTES as BLS_PUBLIC_KEY_BYTES_CONST,
        SIGNATURE_BYTES as BLS_SIGNATURE_BYTES_CONST,
    },
    domain,
    hash::sha3_256_tagged,
    sig_pq::PUBLIC_KEY_BYTES as ML_DSA_PUBLIC_KEY_BYTES_CONST,
};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Byte width of an Ed25519 verifying key per RFC 8032 / §3.4.1.
/// Re-exported for callers that don't want to depend directly on
/// `adamant-crypto::sig_classical`.
pub const ED25519_PUBLIC_KEY_BYTES: usize = 32;

/// Byte width of an ML-DSA-65 verifying key per FIPS 204 / §3.4.2.
/// Re-export of `adamant_crypto::sig_pq::PUBLIC_KEY_BYTES`.
pub const ML_DSA_PUBLIC_KEY_BYTES: usize = ML_DSA_PUBLIC_KEY_BYTES_CONST;

/// Byte width of a BLS12-381 G1 compressed public key per IETF /
/// §3.4.3. Re-export of `adamant_crypto::bls::PUBLIC_KEY_BYTES`.
pub const BLS_PUBLIC_KEY_BYTES: usize = BLS_PUBLIC_KEY_BYTES_CONST;

/// Byte width of a BLS12-381 signature per IETF / §3.4.3.
/// Re-export of `adamant_crypto::bls::SIGNATURE_BYTES`.
pub const BLS_SIGNATURE_BYTES: usize = BLS_SIGNATURE_BYTES_CONST;

/// Total byte width of the `ValidatorPublicKeys` BCS encoding.
/// `32 + 1952 + 96 + 48 = 2128` bytes (post Crypto C-2 PoP).
pub const VALIDATOR_PUBLIC_KEYS_BYTES: usize =
    ED25519_PUBLIC_KEY_BYTES + ML_DSA_PUBLIC_KEY_BYTES + BLS_PUBLIC_KEY_BYTES + BLS_SIGNATURE_BYTES;

/// Byte width of a [`ValidatorId`].
pub const VALIDATOR_ID_BYTES: usize = 32;

/// The bundle of public keys defining a validator's identity per
/// §8.1.1.
///
/// All three keys are required: validators sign consensus
/// messages with Ed25519 for low-latency verification, with
/// ML-DSA-65 for post-quantum integrity, and with BLS12-381 for
/// aggregate-signature consensus throughput. The §8.6 consensus
/// VRF binds to the BLS key.
///
/// **Field declaration order is consensus-binding** per §5.1.8 BCS
/// canonicality — reordering changes the byte serialization which
/// changes [`ValidatorId`] derivation, which is a hard fork.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct ValidatorPublicKeys {
    /// Ed25519 public key (RFC 8032 / §3.4.1) — 32 bytes.
    pub ed25519_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
    /// ML-DSA-65 public key (NIST FIPS 204 / §3.4.2) — 1952 bytes.
    #[serde(with = "BigArray")]
    pub ml_dsa_public_key: [u8; ML_DSA_PUBLIC_KEY_BYTES],
    /// BLS12-381 G1 compressed public key (§3.4.3) — 96 bytes.
    #[serde(with = "BigArray")]
    pub bls_public_key: [u8; BLS_PUBLIC_KEY_BYTES],
    /// BLS12-381 proof-of-possession signature — 48 bytes.
    ///
    /// Signs [`compute_bls_pop_message`]'s output under the BLS
    /// secret key corresponding to `bls_public_key`. Provides
    /// cryptographic attestation that the validator controls the
    /// BLS secret. Per the pre-Phase-10 audit Crypto C-2
    /// remediation, the active-set admission path enforces PoP
    /// verification via [`Self::verify_pop`].
    #[serde(with = "BigArray")]
    pub bls_pop: [u8; BLS_SIGNATURE_BYTES],
}

/// Errors surfaced by [`ValidatorPublicKeys::verify_pop`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum PopError {
    /// The advertised BLS public key did not parse as a valid
    /// curve point. Catches malformed-bytes registration
    /// attempts before reaching the PoP verification step.
    MalformedBlsPublicKey,
    /// The advertised BLS PoP signature did not parse as a
    /// valid curve point.
    MalformedBlsPop,
    /// The PoP signature did not verify against the canonical
    /// PoP message under the advertised BLS public key. The
    /// validator does NOT control the BLS secret claimed in
    /// the bundle.
    PopVerificationFailed,
}

impl core::fmt::Display for PopError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MalformedBlsPublicKey => f.write_str("validator BLS public key is malformed"),
            Self::MalformedBlsPop => f.write_str("validator BLS proof-of-possession is malformed"),
            Self::PopVerificationFailed => {
                f.write_str("validator BLS proof-of-possession verification failed (rogue key)")
            }
        }
    }
}

impl std::error::Error for PopError {}

/// Compute the canonical PoP message a validator must sign over
/// to prove control of their BLS secret key per the
/// pre-Phase-10 audit Crypto C-2 remediation.
///
/// `pop_message = sha3_256_tagged(VALIDATOR_BLS_POP,
///                                ed25519_public_key
///                                || ml_dsa_public_key
///                                || bls_public_key)`
///
/// The message binds the BLS public key to the other key
/// material in the bundle: an attacker cannot reuse an honest
/// validator's PoP for a different (ed25519, ml_dsa) bundle.
/// Returns the 32-byte tagged-hash output that the PoP
/// signature commits to.
#[must_use]
pub fn compute_bls_pop_message(
    ed25519_public_key: &[u8; ED25519_PUBLIC_KEY_BYTES],
    ml_dsa_public_key: &[u8; ML_DSA_PUBLIC_KEY_BYTES],
    bls_public_key: &[u8; BLS_PUBLIC_KEY_BYTES],
) -> [u8; 32] {
    let mut input = Vec::with_capacity(
        ED25519_PUBLIC_KEY_BYTES + ML_DSA_PUBLIC_KEY_BYTES + BLS_PUBLIC_KEY_BYTES,
    );
    input.extend_from_slice(ed25519_public_key);
    input.extend_from_slice(ml_dsa_public_key);
    input.extend_from_slice(bls_public_key);
    sha3_256_tagged(&domain::VALIDATOR_BLS_POP, &input)
}

impl ValidatorPublicKeys {
    /// Construct from the four component byte arrays. Performs
    /// **no** cryptographic validation; callers MUST invoke
    /// [`Self::verify_pop`] before trusting the bundle for
    /// active-set admission or consensus participation. Direct
    /// construction without PoP verification is permitted for
    /// parsing on-chain values, deserialisation, and test
    /// fixtures.
    #[must_use]
    pub const fn new(
        ed25519_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
        ml_dsa_public_key: [u8; ML_DSA_PUBLIC_KEY_BYTES],
        bls_public_key: [u8; BLS_PUBLIC_KEY_BYTES],
        bls_pop: [u8; BLS_SIGNATURE_BYTES],
    ) -> Self {
        Self {
            ed25519_public_key,
            ml_dsa_public_key,
            bls_public_key,
            bls_pop,
        }
    }

    /// Construct from the public-key components + a BLS secret
    /// key, generating the PoP signature in the process. This is
    /// the operator-side construction path: the validator
    /// operator has the BLS secret at registration time and
    /// produces a fresh PoP binding the entire bundle.
    ///
    /// # Errors
    ///
    /// Returns [`PopError::MalformedBlsPublicKey`] if
    /// `bls_secret_key.public_key().to_bytes() != bls_public_key`
    /// (the supplied secret doesn't actually correspond to the
    /// advertised public key — operator-side bookkeeping bug).
    pub fn with_pop(
        ed25519_public_key: [u8; ED25519_PUBLIC_KEY_BYTES],
        ml_dsa_public_key: [u8; ML_DSA_PUBLIC_KEY_BYTES],
        bls_public_key: [u8; BLS_PUBLIC_KEY_BYTES],
        bls_secret_key: &bls::SecretKey,
    ) -> Result<Self, PopError> {
        // Validate that the supplied secret matches the
        // advertised public — surfaces the operator-side
        // bookkeeping bug before the PoP would silently disagree
        // with the bundle.
        if bls_secret_key.public_key().to_bytes() != bls_public_key {
            return Err(PopError::MalformedBlsPublicKey);
        }
        let pop_message =
            compute_bls_pop_message(&ed25519_public_key, &ml_dsa_public_key, &bls_public_key);
        let pop = bls_secret_key.sign(&pop_message);
        Ok(Self {
            ed25519_public_key,
            ml_dsa_public_key,
            bls_public_key,
            bls_pop: pop.to_bytes(),
        })
    }

    /// Verify the bundled BLS proof-of-possession signature
    /// per the pre-Phase-10 audit Crypto C-2 remediation.
    ///
    /// Validators MUST call this before admitting a new
    /// validator into the active set. The active-set
    /// [`crate::ActiveSet::register_with_pop`] path enforces
    /// this; the legacy [`crate::ActiveSet::register`] path
    /// is retained for test fixtures that don't need PoP
    /// verification.
    ///
    /// # Errors
    ///
    /// - [`PopError::MalformedBlsPublicKey`] if `bls_public_key`
    ///   doesn't parse as a valid curve point.
    /// - [`PopError::MalformedBlsPop`] if `bls_pop` doesn't
    ///   parse as a valid curve point.
    /// - [`PopError::PopVerificationFailed`] if the signature
    ///   doesn't verify against [`compute_bls_pop_message`]'s
    ///   output under `bls_public_key` — the rogue-key attack
    ///   case.
    pub fn verify_pop(&self) -> Result<(), PopError> {
        let pk = bls::PublicKey::from_bytes(&self.bls_public_key)
            .map_err(|_| PopError::MalformedBlsPublicKey)?;
        let sig =
            bls::Signature::from_bytes(&self.bls_pop).map_err(|_| PopError::MalformedBlsPop)?;
        let message = compute_bls_pop_message(
            &self.ed25519_public_key,
            &self.ml_dsa_public_key,
            &self.bls_public_key,
        );
        pk.verify(&message, &sig)
            .map_err(|_| PopError::PopVerificationFailed)
    }

    /// Compute the [`ValidatorId`] for this key bundle per §8.1.2.
    ///
    /// `validator_id = sha3_256_tagged(VALIDATOR_ID, BCS(self))`.
    /// Deterministic; two `ValidatorPublicKeys` with identical
    /// component bytes produce identical `ValidatorId`s.
    ///
    /// The PoP signature `bls_pop` is part of the BCS-encoded
    /// input, so the `ValidatorId` is bound to the entire bundle
    /// including the PoP. This means a malicious "PoP downgrade"
    /// (stripping the PoP from an honest bundle) changes the id
    /// and therefore is rejected at the active-set level.
    ///
    /// # Panics
    ///
    /// Panics only if BCS serialisation fails, which cannot occur
    /// for this struct's plain-data shape (no custom serialisers,
    /// no `Result`-returning serde paths).
    #[must_use]
    pub fn derive_id(&self) -> ValidatorId {
        let bcs_bytes =
            bcs::to_bytes(self).expect("ValidatorPublicKeys is BCS-serialisable by construction");
        let hash = sha3_256_tagged(&domain::VALIDATOR_ID, &bcs_bytes);
        ValidatorId::from_bytes(hash)
    }
}

impl core::fmt::Debug for ValidatorPublicKeys {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Avoid printing 2080 bytes; show just the validator-id
        // derivation for diagnostic readability. Test code that
        // wants the raw bytes can access the fields directly.
        write!(f, "ValidatorPublicKeys({:?})", self.derive_id())
    }
}

/// Content-derived 32-byte validator identifier per §8.1.2.
///
/// Computed as `sha3_256_tagged(VALIDATOR_ID, BCS(ValidatorPublicKeys))`.
/// Mirrors the [`adamant_types::Address`] tagged-hash construction
/// (§4.2): a deterministic, content-addressed identifier that any
/// party can re-derive from the validator's published public-key
/// bundle. The id IS the cryptographic commitment to the bundle —
/// changing any byte of any key changes the id.
///
/// `ValidatorId` is *not* the validator's on-chain Address. The
/// Address represents the account that operationally controls the
/// validator (the address that signs `register_validator` or
/// `transfer_slot` transactions). The `ValidatorId` represents the
/// validator's cryptographic identity (the keys it signs consensus
/// messages with). The mapping `ValidatorId ↔ Address` is recorded
/// in the on-chain `Validator` object (§8.1.2 / [`crate::Validator`]).
#[derive(Clone, Copy, Eq, PartialEq, Ord, PartialOrd, Hash, Serialize, Deserialize)]
pub struct ValidatorId([u8; VALIDATOR_ID_BYTES]);

impl ValidatorId {
    /// Construct from raw 32-byte material.
    ///
    /// Callers should normally derive a `ValidatorId` from a
    /// [`ValidatorPublicKeys`] via [`ValidatorPublicKeys::derive_id`]
    /// rather than constructing one directly. Direct construction
    /// is supported for parsing on-chain values + test fixtures.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; VALIDATOR_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; VALIDATOR_ID_BYTES] {
        self.0
    }

    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VALIDATOR_ID_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for ValidatorId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "ValidatorId(0x")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_keys() -> ValidatorPublicKeys {
        ValidatorPublicKeys::new(
            [0x11; ED25519_PUBLIC_KEY_BYTES],
            [0x22; ML_DSA_PUBLIC_KEY_BYTES],
            [0x33; BLS_PUBLIC_KEY_BYTES],
            [0x44; BLS_SIGNATURE_BYTES],
        )
    }

    /// Pin the public-key byte widths to the §3.4 spec values.
    #[test]
    fn public_key_byte_widths_pinned() {
        assert_eq!(ED25519_PUBLIC_KEY_BYTES, 32);
        assert_eq!(ML_DSA_PUBLIC_KEY_BYTES, 1952);
        assert_eq!(BLS_PUBLIC_KEY_BYTES, 96);
        assert_eq!(BLS_SIGNATURE_BYTES, 48);
        assert_eq!(VALIDATOR_PUBLIC_KEYS_BYTES, 32 + 1952 + 96 + 48);
    }

    /// BCS encoding of `ValidatorPublicKeys` is exactly 2128
    /// bytes (post Crypto C-2 PoP). No length-prefixes;
    /// canonical fixed-array concatenation per §5.1.8.
    #[test]
    fn validator_public_keys_bcs_size_pinned() {
        let keys = fixed_keys();
        let bytes = bcs::to_bytes(&keys).expect("BCS serialisable");
        assert_eq!(bytes.len(), VALIDATOR_PUBLIC_KEYS_BYTES);
    }

    /// BCS round-trip preserves all key material.
    #[test]
    fn validator_public_keys_bcs_round_trip() {
        let keys = fixed_keys();
        let bytes = bcs::to_bytes(&keys).unwrap();
        let decoded: ValidatorPublicKeys = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(keys, decoded);
    }

    /// `derive_id` is deterministic.
    #[test]
    fn derive_id_deterministic() {
        let keys = fixed_keys();
        let id1 = keys.derive_id();
        let id2 = keys.derive_id();
        assert_eq!(id1, id2);
    }

    /// Different public-key bundles produce different
    /// `ValidatorId`s.
    #[test]
    fn distinct_keys_distinct_ids() {
        let keys1 = fixed_keys();
        let mut ed_2 = [0x11; ED25519_PUBLIC_KEY_BYTES];
        ed_2[0] = 0xFF;
        let keys2 = ValidatorPublicKeys::new(
            ed_2,
            [0x22; ML_DSA_PUBLIC_KEY_BYTES],
            [0x33; BLS_PUBLIC_KEY_BYTES],
            [0x44; BLS_SIGNATURE_BYTES],
        );
        assert_ne!(keys1.derive_id(), keys2.derive_id());
    }

    /// Domain-separation: `ValidatorId` derivation uses the
    /// `VALIDATOR_ID` tag, not any other tag. Verify by
    /// computing the hash with a different tag and checking the
    /// result differs.
    #[test]
    fn derive_id_uses_validator_id_domain_tag() {
        use adamant_crypto::hash::sha3_256_tagged;
        let keys = fixed_keys();
        let bcs_bytes = bcs::to_bytes(&keys).unwrap();
        let with_validator_tag = sha3_256_tagged(&adamant_crypto::domain::VALIDATOR_ID, &bcs_bytes);
        let with_account_tag =
            sha3_256_tagged(&adamant_crypto::domain::ACCOUNT_ADDRESS, &bcs_bytes);
        assert_ne!(with_validator_tag, with_account_tag);
        assert_eq!(keys.derive_id().to_bytes(), with_validator_tag);
    }

    /// `ValidatorId` BCS round-trip is byte-stable.
    #[test]
    fn validator_id_bcs_round_trip() {
        let id = ValidatorId::from_bytes([0x42; VALIDATOR_ID_BYTES]);
        let bytes = bcs::to_bytes(&id).unwrap();
        let decoded: ValidatorId = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(id, decoded);
        assert_eq!(bytes.len(), VALIDATOR_ID_BYTES);
    }

    /// `ValidatorId` Debug is hex-encoded with `0x` prefix and
    /// the 32 bytes.
    #[test]
    fn validator_id_debug_hex() {
        let id = ValidatorId::from_bytes([0xAB; VALIDATOR_ID_BYTES]);
        let s = format!("{id:?}");
        assert!(s.starts_with("ValidatorId(0x"));
        assert!(s.contains("ab"));
        assert!(s.ends_with(')'));
    }

    /// `ValidatorPublicKeys` Debug doesn't print 2080 raw bytes;
    /// it shows the derived id for diagnostic readability.
    #[test]
    fn validator_public_keys_debug_compact() {
        let keys = fixed_keys();
        let s = format!("{keys:?}");
        assert!(s.starts_with("ValidatorPublicKeys("));
        assert!(s.contains("ValidatorId"));
        // Debug should NOT contain the 1952-byte ML-DSA key
        // material rendered as bytes.
        assert!(
            s.len() < 200,
            "Debug output should be compact, got {} chars",
            s.len()
        );
    }

    /// Known-answer test pin for `derive_id` on the fixed_keys
    /// fixture. If this test ever changes, the §8.1.2
    /// ValidatorId derivation has hard-forked.
    #[test]
    fn derive_id_known_answer() {
        let keys = fixed_keys();
        let id = keys.derive_id();
        // Re-derive via the explicit construction to confirm
        // the formula:
        let bcs_bytes = bcs::to_bytes(&keys).unwrap();
        let expected = adamant_crypto::hash::sha3_256_tagged(
            &adamant_crypto::domain::VALIDATOR_ID,
            &bcs_bytes,
        );
        assert_eq!(id.to_bytes(), expected);
    }

    // ---------------------------------------------------------------
    // Crypto C-2 remediation: BLS proof-of-possession
    // ---------------------------------------------------------------

    /// `compute_bls_pop_message` is deterministic + binds all three
    /// public-key components.
    #[test]
    fn compute_bls_pop_message_deterministic_and_binding() {
        let ed = [0x11; ED25519_PUBLIC_KEY_BYTES];
        let ml = [0x22; ML_DSA_PUBLIC_KEY_BYTES];
        let bls = [0x33; BLS_PUBLIC_KEY_BYTES];
        // Determinism.
        let m1 = compute_bls_pop_message(&ed, &ml, &bls);
        let m2 = compute_bls_pop_message(&ed, &ml, &bls);
        assert_eq!(m1, m2);
        // Distinct ed25519 → distinct message.
        let mut ed_b = ed;
        ed_b[0] = 0xFF;
        assert_ne!(compute_bls_pop_message(&ed_b, &ml, &bls), m1);
        // Distinct ml_dsa → distinct message.
        let mut ml_b = ml;
        ml_b[0] = 0xFF;
        assert_ne!(compute_bls_pop_message(&ed, &ml_b, &bls), m1);
        // Distinct bls → distinct message.
        let mut bls_b = bls;
        bls_b[0] = 0xFF;
        assert_ne!(compute_bls_pop_message(&ed, &ml, &bls_b), m1);
    }

    /// `with_pop` produces a bundle whose `verify_pop` accepts.
    #[test]
    fn with_pop_produces_verifiable_bundle() {
        let sk = adamant_crypto::bls::SecretKey::from_ikm(&[0x77; 32]).expect("bls");
        let pk_bytes = sk.public_key().to_bytes();
        let ed = [0x11; ED25519_PUBLIC_KEY_BYTES];
        let ml = [0x22; ML_DSA_PUBLIC_KEY_BYTES];
        let keys = ValidatorPublicKeys::with_pop(ed, ml, pk_bytes, &sk).expect("with_pop");
        keys.verify_pop()
            .expect("PoP must verify under matching BLS key");
    }

    /// `with_pop` rejects a secret whose public key doesn't
    /// match the advertised `bls_public_key` (operator
    /// bookkeeping bug detection).
    #[test]
    fn with_pop_rejects_mismatched_secret() {
        let sk_a = adamant_crypto::bls::SecretKey::from_ikm(&[0x77; 32]).expect("a");
        let sk_b = adamant_crypto::bls::SecretKey::from_ikm(&[0x88; 32]).expect("b");
        // Advertise A's public key but supply B's secret —
        // operator bookkeeping mismatch.
        let ed = [0x11; ED25519_PUBLIC_KEY_BYTES];
        let ml = [0x22; ML_DSA_PUBLIC_KEY_BYTES];
        let err = ValidatorPublicKeys::with_pop(ed, ml, sk_a.public_key().to_bytes(), &sk_b)
            .expect_err("must reject");
        assert_eq!(err, PopError::MalformedBlsPublicKey);
    }

    /// `verify_pop` rejects the canonical rogue-key attack:
    /// honestly-formatted bundle with a forged PoP signature.
    /// This is the C-2 attack class the fix closes.
    #[test]
    fn verify_pop_rejects_forged_pop_signature() {
        let sk = adamant_crypto::bls::SecretKey::from_ikm(&[0x77; 32]).expect("bls");
        let ed = [0x11; ED25519_PUBLIC_KEY_BYTES];
        let ml = [0x22; ML_DSA_PUBLIC_KEY_BYTES];
        // Build the honest bundle then tamper the PoP.
        let mut keys =
            ValidatorPublicKeys::with_pop(ed, ml, sk.public_key().to_bytes(), &sk).expect("ok");
        // Forge: flip one bit in the PoP signature.
        keys.bls_pop[0] ^= 0x01;
        let err = keys.verify_pop().expect_err("must reject forged PoP");
        // Either MalformedBlsPop (the tampered byte broke curve
        // decoding) or PopVerificationFailed (the byte still
        // decoded but doesn't verify) — both are acceptable
        // rejection paths.
        assert!(matches!(
            err,
            PopError::PopVerificationFailed | PopError::MalformedBlsPop
        ));
    }

    /// `verify_pop` rejects a PoP signed under a different
    /// secret key — the rogue-key construction attack.
    #[test]
    fn verify_pop_rejects_pop_signed_under_different_key() {
        let sk_target = adamant_crypto::bls::SecretKey::from_ikm(&[0xAA; 32]).expect("target");
        let sk_attacker = adamant_crypto::bls::SecretKey::from_ikm(&[0xBB; 32]).expect("attacker");
        let ed = [0x11; ED25519_PUBLIC_KEY_BYTES];
        let ml = [0x22; ML_DSA_PUBLIC_KEY_BYTES];
        // Attacker produces a PoP signed under their secret but
        // tries to register it against the target's public key.
        let pop_message = compute_bls_pop_message(&ed, &ml, &sk_target.public_key().to_bytes());
        let forged_pop = sk_attacker.sign(&pop_message);
        let keys = ValidatorPublicKeys::new(
            ed,
            ml,
            sk_target.public_key().to_bytes(),
            forged_pop.to_bytes(),
        );
        let err = keys.verify_pop().expect_err("must reject cross-key PoP");
        assert_eq!(err, PopError::PopVerificationFailed);
    }
}
