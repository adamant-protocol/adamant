//! Time-lock encryption (Wesolowski VDF) per whitepaper §3.8.
//!
//! Phase 7.5 (time-lock VDF sub-arc) — Adamant-native Wesolowski
//! VDF over class groups of imaginary quadratic order per
//! whitepaper §3.8.1. This module hosts the cryptographic
//! primitive surface; the consensus-side wiring (round-anchor
//! binding, two-regime hysteresis with the §8.4.2 viability
//! boundary) lives in `adamant-consensus` and lands at the
//! Phase 7.6 mempool sub-arc.
//!
//! # Spec basis
//!
//! Whitepaper §3.8.1 (verbatim): "The protocol uses the
//! Wesolowski VDF (Wesolowski 2019) over class groups of
//! imaginary quadratic order (or, optionally, over RSA groups;
//! the choice is implementation-defined and does not affect
//! protocol correctness). Class groups are preferred because
//! they require no trusted setup — there is no group element
//! whose secret factorisation could compromise the
//! construction."
//!
//! Whitepaper §3.8.1 enumerates four operations:
//!
//! 1. **Setup.** A class group of unknown order is fixed at
//!    protocol initialisation. The group's parameters are
//!    derived deterministically from the genesis state
//!    (§11.2.8) using a hash-to-class-group construction.
//!    There is no secret involved.
//! 2. **Encryption.** A user encrypts a transaction by sampling
//!    a random group element `g` and computing `h = g^(2^T)`
//!    for the time-lock parameter `T`. The transaction's
//!    symmetric encryption key is derived from `h`. The user
//!    publishes `g`, the symmetric ciphertext, and a Wesolowski
//!    proof of knowledge of `h` (this last is required only to
//!    prevent malformed envelopes, not for security against
//!    time-locked decryption).
//! 3. **Decryption.** A validator (specifically, the round
//!    anchor for the round in which the transaction is
//!    included; §8.4.4) computes `h = g^(2^T)` by performing
//!    `T` sequential squarings, then derives the symmetric key
//!    and decrypts. The computation is by construction
//!    sequential — no parallel speedup exists.
//! 4. **Verification.** Any party can verify that the published
//!    `h` is correct given `g` and `T` by checking the
//!    Wesolowski proof. The proof is a single class-group
//!    element and verifies in constant time.
//!
//! Whitepaper §3.8.2 pins parameter selection: discriminant
//! size ≥ 2048 bits (≈128-bit classical security) and
//! `T ∈ [2_000_000, 7_500_000]` calibrated to produce 10–15
//! seconds of decryption time on consensus-grade hardware.
//! The exact `T` value is calibrated empirically before genesis
//! and committed as a chain-state parameter at activation
//! (§3.8.2; pre-mainnet calibration item per CLAUDE.md
//! Section 10 "Calibration work pending").
//!
//! Whitepaper §3.8.3 pins public verifiability: Wesolowski's
//! construction satisfies this requirement; "black-box VDFs
//! that produce only the output without a verification proof
//! are explicitly excluded". The §8.4.4 anchor-rotation and
//! decryption-publication-binding mitigations depend on
//! observers being able to verify the round anchor's
//! decryption-evaluation proof.
//!
//! # Phase 7.5 sub-arc shape
//!
//! Phase 7.5 is broken into sub-arcs to keep each step
//! reviewable. This module is the **Phase 7.5.0 foundation**:
//!
//! | Sub-arc | Surface | Status |
//! |---------|---------|--------|
//! | 7.5.0   | wire types + domain tags + BCS encoding | **THIS SUB-ARC** |
//! | 7.5.1   | class-group arithmetic (binary quadratic forms, NUDPL squaring, reduction) | pending |
//! | 7.5.2   | hash-to-class-group setup per §3.8.1 + §11.2.8 | pending |
//! | 7.5.3   | VDF evaluation (`evaluate`: T sequential squarings) | pending |
//! | 7.5.4   | Wesolowski proof generation (`prove`: Fiat-Shamir + π = g^q) | pending |
//! | 7.5.5   | Wesolowski proof verification (`verify`: π^ℓ · g^r ?= h) | pending |
//! | 7.5.6   | symmetric-key derivation + AEAD envelope wrapper | pending |
//!
//! The 7.5.0 surface is consensus-stable: parameter byte
//! strings, group-element BCS encoding, proof BCS encoding,
//! envelope BCS encoding, and the `VdfError` variant tags all
//! pin here. Sub-arcs 7.5.1+ add operations against these
//! types; no type-shape changes are anticipated past this
//! foundation.
//!
//! # Adamant-native posture
//!
//! Per CLAUDE.md §14 (the project-wide Adamant-native
//! commitment) and §13 (resistant-proof posture), the Wesolowski
//! VDF math is implemented in Adamant code rather than pulled in
//! as an external dependency. Class-group arithmetic in Rust
//! requires no exotic primitives beyond big-integer arithmetic;
//! the implementation will layer over `num-bigint` or a Adamant-
//! native `BigInt` only after explicit spec-author ratification of
//! the dependency choice at the Phase 7.5.1 plan-gate.
//!
//! Same pattern as KZG (whitepaper §3.9.2 amendment, instance
//! 30): a peer-reviewed cryptographic primitive (Wesolowski 2019)
//! implemented Adamant-native rather than via `class_group` or
//! `rsa-vdf` crates.
//!
//! # What this module ships at Phase 7.5.0
//!
//! - [`TimeLockParameters`] — the genesis-fixed `(discriminant,
//!   time_parameter_t)` parameter bundle.
//! - [`ClassGroupElement`] — opaque, length-prefixed encoding of
//!   a single class-group element. Internal byte layout (binary
//!   quadratic form `(a, b)` with `c` recoverable from
//!   `c = (b² − D) / (4a)`) is pinned at Phase 7.5.1; this layer
//!   stores the canonical encoding as an opaque `Vec<u8>` so
//!   wire types are forward-stable.
//! - [`WesolowskiProof`] — the single-class-group-element proof
//!   `π = g^q` where `q = ⌊2^T / ℓ⌋` for the Fiat-Shamir prime
//!   challenge `ℓ` per Wesolowski 2019 §3.
//! - [`TimeLockEnvelope`] — the user-submitted ciphertext
//!   `(puzzle: g, ciphertext, well_formedness_proof)` per §3.8.1
//!   step 2 ("Encryption").
//! - [`TimeLockDecryption`] — the anchor-published clear-text
//!   binding `(solution: h, evaluation_proof)` per §3.8.1 step 3
//!   ("Decryption") + §3.8.1 step 4 ("Verification") + §8.4.4
//!   Mitigation B ("Decryption-publication binding").
//! - [`VdfError`] — typed error variants spanning malformed-
//!   encoding, parameter-mismatch, and proof-verification
//!   failures. The variants pin here; Phase 7.5.1+ adds operation
//!   sites that produce them.
//!
//! # What this module does NOT ship at Phase 7.5.0
//!
//! - **Class-group arithmetic.** Composition (NUDPL), squaring,
//!   exponentiation, reduction — lands at Phase 7.5.1.
//! - **Hash-to-class-group setup.** The deterministic derivation
//!   of the class-group discriminant from the genesis state per
//!   §11.2.8 — lands at Phase 7.5.2.
//! - **VDF operations.** `evaluate`, `prove`, `verify` — lands
//!   at Phase 7.5.3–7.5.5.
//! - **Envelope encryption.** Wiring `TimeLockEnvelope` to
//!   ChaCha20-Poly1305 via the [`TIME_LOCK_SYMMETRIC_KEY`]
//!   domain tag — lands at Phase 7.5.6.
//!
//! Per Adamant's "never ship stub crypto functions" discipline,
//! this module deliberately exposes no `evaluate` / `prove` /
//! `verify` functions yet. Phase 7.5.1+ adds them as honest,
//! tested implementations against these types.
//!
//! [`TIME_LOCK_SYMMETRIC_KEY`]: crate::domain::TIME_LOCK_SYMMETRIC_KEY

pub mod bqf;
pub mod modular;
pub mod setup;
pub mod wesolowski;

use core::fmt;

use serde::{Deserialize, Serialize};

/// Genesis-fixed Wesolowski VDF parameters per whitepaper
/// §3.8.1 + §3.8.2.
///
/// The parameter bundle is committed at activation
/// (§3.8.1 "Setup"; §11.2.8 genesis state) and is immutable
/// over the lifetime of the chain. Two parameters fix the
/// construction:
///
/// - **`discriminant`** — the class-group discriminant `D`,
///   a negative integer derived deterministically from the
///   genesis state (§11.2.8). `|D|` is sized for ≥128-bit
///   classical security; per §3.8.2 the canonical size is
///   2048 bits, so the byte vector is typically 256 bytes
///   wide. The encoding is **big-endian two's-complement**:
///   the high bit of the first byte indicates the sign (`1`
///   for negative). Phase 7.5.1 pins the exact derivation
///   construction; this field is the opaque byte string in
///   the meantime.
///
/// - **`time_parameter_t`** — the time-lock parameter `T`
///   per §3.8.2. The protocol target is `T ∈ [2_000_000,
///   7_500_000]`, calibrated empirically before genesis to
///   produce 10–15 seconds of decryption time on consensus-
///   grade hardware (200,000–500,000 class-group squarings
///   per second). The exact value is committed at activation
///   per §3.8.2 ("The exact value is calibrated empirically
///   before genesis and committed as a chain-state
///   parameter").
///
/// # BCS encoding
///
/// BCS-encoded `TimeLockParameters` is a length-prefixed
/// byte vector (the discriminant) followed by a fixed 8-byte
/// little-endian `u64` (the time parameter). Byte size is
/// variable: `bcs_uleb128_len(D.len()) + D.len() + 8`.
///
/// # Chain-state commitment
///
/// Every node at startup re-derives the chain-state
/// commitment over the genesis-fixed parameters via
/// [`parameter_commitment`] and compares against the genesis-
/// published commitment. Any drift in parameter bytes surfaces
/// as a commitment mismatch — the same posture as Adamant's
/// other chain-state-fixed cryptographic parameters (§3.6
/// threshold-encryption KDF salt, §3.9.2 KZG trusted setup).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeLockParameters {
    /// The class-group discriminant `D`. Negative integer in
    /// big-endian two's-complement encoding. Width is set at
    /// activation per §3.8.2 (≥256 bytes for ≥2048-bit
    /// discriminant). Phase 7.5.2 pins the deterministic
    /// derivation per §11.2.8.
    pub discriminant: Vec<u8>,

    /// The time-lock parameter `T` per §3.8.2. Number of
    /// sequential class-group squarings required to evaluate
    /// `h = g^(2^T)`.
    pub time_parameter_t: u64,
}

impl TimeLockParameters {
    /// Computes the chain-state commitment over these
    /// parameters via the BIP-340 tagged-SHA3-256
    /// construction with the [`TIME_LOCK_PARAMETERS`] domain
    /// tag.
    ///
    /// Composition:
    ///
    /// ```text
    /// parameter_commitment = sha3_256_tagged(
    ///     TIME_LOCK_PARAMETERS,
    ///     BCS(TimeLockParameters)
    /// )
    /// ```
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: `TimeLockParameters` is a
    /// plain-data struct with derived `Serialize`, and the
    /// derived BCS encoding is total over all valid values.
    ///
    /// [`TIME_LOCK_PARAMETERS`]: crate::domain::TIME_LOCK_PARAMETERS
    #[must_use]
    pub fn parameter_commitment(&self) -> [u8; 32] {
        let bytes = bcs::to_bytes(self).expect("TimeLockParameters is BCS-serialisable");
        crate::hash::sha3_256_tagged(&crate::domain::TIME_LOCK_PARAMETERS, &bytes)
    }
}

/// An opaque encoding of a single class-group element per
/// whitepaper §3.8.1.
///
/// Class-group elements are represented internally as
/// **reduced binary quadratic forms** `(a, b, c)` over the
/// imaginary quadratic order of discriminant `D`, where
/// `4ac − b² = −D`. The canonical encoding stores `(a, b)`
/// only — `c` is recoverable as `c = (b² + |D|) / (4a)`.
///
/// The exact encoding (byte widths for `a` and `b`, sign-bit
/// placement, normalised-form invariants for reduced forms)
/// is pinned at Phase 7.5.1 when the arithmetic implementation
/// lands. This 7.5.0 layer stores the canonical encoding as an
/// opaque `Vec<u8>` so wire types are forward-stable: a
/// `ClassGroupElement` value that round-trips through BCS at
/// 7.5.0 will round-trip identically after 7.5.1 pins the
/// internal layout.
///
/// # Equality
///
/// Two `ClassGroupElement` values are byte-equal iff their
/// canonical encodings are byte-equal. Phase 7.5.1's reduction
/// invariant (every reduced form has a unique canonical
/// representation) makes byte-equality and group-equality
/// equivalent — a property the consensus layer relies on for
/// equivocation detection (§8.1.5).
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ClassGroupElement {
    /// Canonical encoding of a reduced binary quadratic form.
    /// Internal layout pinned at Phase 7.5.1.
    pub encoded: Vec<u8>,
}

impl ClassGroupElement {
    /// Constructs a `ClassGroupElement` from a pre-encoded byte
    /// string. The bytes are not validated against the
    /// reduced-form invariants at this layer; Phase 7.5.1
    /// introduces a validating constructor that rejects
    /// non-reduced encodings via [`VdfError::MalformedEncoding`].
    #[must_use]
    pub fn from_bytes(encoded: Vec<u8>) -> Self {
        Self { encoded }
    }

    /// Returns the canonical encoding as a byte slice.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.encoded
    }
}

/// A Wesolowski VDF proof per whitepaper §3.8.1 + §3.8.3.
///
/// The proof attests "I know `h` such that `h = g^(2^T)`
/// under the chain-fixed parameters". Per §3.8.3 the proof is
/// **publicly verifiable** — any party with `(g, h, T)` and the
/// proof element `π` can confirm the attestation in constant
/// time, without performing `T` squarings themselves.
///
/// # Construction (Wesolowski 2019 §3)
///
/// Given `(g, h, T)`:
///
/// 1. Derive the Fiat-Shamir prime challenge
///    `ℓ = HashToPrime(g, h, T)` via the
///    [`WESOLOWSKI_CHALLENGE`] domain tag (Phase 7.5.4 pins
///    the exact derivation).
/// 2. Compute the quotient `q = ⌊2^T / ℓ⌋` and the remainder
///    `r = 2^T mod ℓ`.
/// 3. The proof is `π = g^q`.
///
/// Verification (Phase 7.5.5) checks `π^ℓ · g^r ≡ h` in the
/// class group; this holds iff the prover knows the correct
/// `h = g^(2^T)`.
///
/// # Soundness
///
/// Wesolowski's soundness proof reduces to the **adaptive
/// root assumption** in groups of unknown order, which is
/// the central assumption underlying class-group VDFs and is
/// conjectured to hold against both classical and quantum
/// adversaries (§3.8.4).
///
/// [`WESOLOWSKI_CHALLENGE`]: crate::domain::WESOLOWSKI_CHALLENGE
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WesolowskiProof {
    /// The single class-group element `π = g^q` where
    /// `q = ⌊2^T / ℓ⌋` for the Fiat-Shamir prime challenge `ℓ`.
    pub pi: ClassGroupElement,
}

/// A user-submitted time-lock-encrypted envelope per whitepaper
/// §3.8.1 step 2 ("Encryption").
///
/// During the time-lock regime (§8.4.4: `N < 15` per the
/// §8.4.2 viability boundary), users encrypt transactions to
/// the protocol's time-lock VDF by:
///
/// 1. Sampling a random class-group element `g`.
/// 2. Computing `h = g^(2^T)` via `T` sequential squarings.
///    (The user pays this cost up-front to ensure the
///    decryption-time computation is bounded.)
/// 3. Deriving the symmetric key
///    `key = shake_256_tagged(TIME_LOCK_SYMMETRIC_KEY, BCS(h), 32)`
///    via the [`TIME_LOCK_SYMMETRIC_KEY`] domain tag.
/// 4. Encrypting the transaction body under ChaCha20-Poly1305
///    with this key (§3.5).
/// 5. Producing a Wesolowski proof
///    `(g, h) ⊢ well_formedness_proof` so validators can
///    reject malformed envelopes without performing `T`
///    squarings themselves per §3.8.1 ("required only to
///    prevent malformed envelopes, not for security against
///    time-locked decryption").
/// 6. Publishing `(puzzle: g, ciphertext, well_formedness_proof)`.
///
/// The user does NOT publish `h` — that's what the time-lock
/// hides. The round anchor recovers `h` by performing the `T`
/// squarings themselves during the decryption window.
///
/// # Phase 7.5.0 — wire surface only
///
/// This type carries the BCS-stable wire format. Encryption /
/// decryption operations land at Phase 7.5.6 alongside the
/// AEAD-envelope wiring.
///
/// [`TIME_LOCK_SYMMETRIC_KEY`]: crate::domain::TIME_LOCK_SYMMETRIC_KEY
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeLockEnvelope {
    /// The user-sampled class-group element `g` that the round
    /// anchor will sequentially square `T` times to derive `h`.
    pub puzzle: ClassGroupElement,

    /// The ChaCha20-Poly1305 ciphertext of the transaction
    /// body encrypted under the symmetric key derived from
    /// `h`. The 12-byte ChaCha20-Poly1305 nonce per §3.5 is
    /// prefixed inside this byte string; the exact framing is
    /// pinned at Phase 7.5.6.
    pub ciphertext: Vec<u8>,

    /// User-produced Wesolowski proof attesting that the user
    /// computed `h = g^(2^T)` correctly. Required only to
    /// prevent malformed envelopes per §3.8.1; absent this
    /// proof, a malicious user could publish a `g` whose `h`
    /// the round anchor cannot derive in finite time (e.g., by
    /// claiming an `h` that has no preimage at all under the
    /// VDF), wasting the anchor's `T`-squaring effort.
    pub well_formedness_proof: WesolowskiProof,
}

/// A round-anchor-published time-lock decryption per whitepaper
/// §3.8.1 step 3 ("Decryption") + §8.4.4 Mitigation B
/// ("Decryption-publication binding").
///
/// During the time-lock regime, the round anchor for each round
/// (selected deterministically by the consensus VRF per §8.6)
/// is the only validator authorised to decrypt envelopes for
/// that round. The anchor:
///
/// 1. Performs `T` sequential squarings of each envelope's
///    `puzzle` to derive `solution = h = puzzle^(2^T)`.
/// 2. Derives the symmetric key from `solution` (same
///    derivation as the user used at encryption time).
/// 3. Decrypts the envelope's ciphertext under that key.
/// 4. Publishes `(solution, evaluation_proof)` **atomically**
///    with the anchor's vertex (§8.4.4 Mitigation B) so other
///    validators can verify the decryption was correct and
///    re-derive the symmetric key + plaintext without
///    performing `T` squarings themselves.
///
/// Per §8.4.4 Mitigation B, the decryption is bound to the
/// anchor's vertex: equivocation (publishing two different
/// vertices, hence two different decryption sets, for the same
/// round) is slashable at 100% of stake per §8.1.5
/// `SlashOffence::Equivocation` (Phase 7.10).
///
/// # Phase 7.5.0 — wire surface only
///
/// This type carries the BCS-stable wire format. The
/// evaluate-and-prove operation lands at Phase 7.5.3 + 7.5.4;
/// the verify operation lands at Phase 7.5.5.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TimeLockDecryption {
    /// The recovered class-group element `h = g^(2^T)` where
    /// `g` is the corresponding envelope's `puzzle`. Used by
    /// other validators to re-derive the symmetric key and
    /// recover the plaintext.
    pub solution: ClassGroupElement,

    /// The anchor's Wesolowski proof attesting `solution =
    /// puzzle^(2^T)` is correct, so observers can verify
    /// without performing `T` squarings themselves per §3.8.3
    /// ("publicly verifiable").
    pub evaluation_proof: WesolowskiProof,
}

/// Typed errors produced by Wesolowski VDF operations.
///
/// All variants are explicit and non-`#[non_exhaustive]`: the
/// time-lock encryption surface is consensus-critical per
/// §8.4.4 and the protocol cannot grow new failure modes
/// silently. Adding a variant is a hard-fork-aware deliberate
/// change.
///
/// # Phase 7.5.0 — variants pin here
///
/// The variants are introduced now so Phase 7.5.1+ operation
/// sites can `return Err(VdfError::…)` against a stable enum.
/// No operation in this module produces these errors at 7.5.0
/// (there are no operations); the variants are the consensus-
/// stable wire-error surface.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VdfError {
    /// A `ClassGroupElement`, `WesolowskiProof`, or other
    /// VDF-domain value failed canonical-encoding validation.
    /// Phase 7.5.1 introduces the per-encoding check; this
    /// variant is the error surface those checks return.
    MalformedEncoding,

    /// An operation was attempted against parameters that do
    /// not match the chain-state-fixed `TimeLockParameters`
    /// (e.g., discriminant mismatch or `T` mismatch). The
    /// round-anchor decryption path uses the chain-fixed
    /// parameters by construction; this error fires on caller-
    /// supplied parameter sets.
    ParameterMismatch,

    /// A Wesolowski proof failed verification — `π^ℓ · g^r`
    /// did not equal `h` in the class group. Phase 7.5.5 is
    /// the production site.
    ProofVerificationFailed,

    /// Symmetric decryption of a `TimeLockEnvelope` ciphertext
    /// failed under the derived key. Phase 7.5.6 is the
    /// production site. Indicates either a malformed envelope
    /// (mismatched puzzle + ciphertext) or anchor / user
    /// disagreement on the symmetric-key derivation (a
    /// consensus-violation surface).
    DecryptionFailed,
}

impl fmt::Display for VdfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::MalformedEncoding => {
                f.write_str("malformed encoding of a VDF value (class-group element or proof)")
            }
            Self::ParameterMismatch => f.write_str(
                "VDF operation parameters do not match the chain-state-fixed parameters",
            ),
            Self::ProofVerificationFailed => {
                f.write_str("Wesolowski proof verification failed: π^ℓ · g^r ≠ h")
            }
            Self::DecryptionFailed => {
                f.write_str("time-lock envelope symmetric decryption failed under the derived key")
            }
        }
    }
}

impl std::error::Error for VdfError {}

#[cfg(test)]
mod tests {
    use super::*;

    /// Constructs a small placeholder discriminant for byte-
    /// shape tests. The real chain-state-fixed discriminant is
    /// derived at Phase 7.5.2 per §11.2.8; this fixture is for
    /// wire-format pinning only.
    fn fixture_discriminant() -> Vec<u8> {
        // Negative 2048-bit integer in two's-complement big-endian
        // representation would be 256 bytes; this fixture is 32 bytes
        // for test-readability (Phase 7.5.0 pins the BCS wire shape,
        // not the cryptographic width — that's a 7.5.2 plan-gate item).
        let mut bytes = vec![0xFFu8; 32];
        bytes[0] = 0xC0; // a high bit set so the value is "negative" by convention
        bytes
    }

    fn fixture_element(seed: u8) -> ClassGroupElement {
        // Phase 7.5.0 stores the element as opaque bytes; this fixture
        // builds a deterministic byte string for round-trip testing.
        ClassGroupElement::from_bytes(vec![seed; 48])
    }

    fn fixture_parameters() -> TimeLockParameters {
        TimeLockParameters {
            discriminant: fixture_discriminant(),
            time_parameter_t: 2_000_000,
        }
    }

    fn fixture_proof() -> WesolowskiProof {
        WesolowskiProof {
            pi: fixture_element(0x01),
        }
    }

    fn fixture_envelope() -> TimeLockEnvelope {
        TimeLockEnvelope {
            puzzle: fixture_element(0x02),
            ciphertext: vec![0xAB; 64],
            well_formedness_proof: fixture_proof(),
        }
    }

    fn fixture_decryption() -> TimeLockDecryption {
        TimeLockDecryption {
            solution: fixture_element(0x03),
            evaluation_proof: fixture_proof(),
        }
    }

    #[test]
    fn time_lock_parameters_bcs_round_trip() {
        let params = fixture_parameters();
        let bytes = bcs::to_bytes(&params).expect("serialise");
        let recovered: TimeLockParameters = bcs::from_bytes(&bytes).expect("deserialise");
        assert_eq!(params, recovered);
    }

    #[test]
    fn time_lock_parameters_encoding_layout_is_length_prefixed_vec_then_u64() {
        // BCS encodes Vec<u8> as ULEB128(len) || bytes, then u64 as
        // 8 little-endian bytes. Pin the exact layout here so any
        // future drift surfaces as a test-time signal.
        let params = TimeLockParameters {
            discriminant: vec![0xAA, 0xBB, 0xCC],
            time_parameter_t: 0x0102_0304_0506_0708,
        };
        let bytes = bcs::to_bytes(&params).expect("serialise");
        assert_eq!(bytes[0], 0x03, "discriminant length prefix (ULEB128 of 3)");
        assert_eq!(&bytes[1..4], &[0xAA, 0xBB, 0xCC], "discriminant bytes");
        assert_eq!(
            &bytes[4..12],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01],
            "time_parameter_t as little-endian u64"
        );
        assert_eq!(bytes.len(), 12);
    }

    #[test]
    fn class_group_element_bcs_round_trip() {
        let element = fixture_element(0xAB);
        let bytes = bcs::to_bytes(&element).expect("serialise");
        let recovered: ClassGroupElement = bcs::from_bytes(&bytes).expect("deserialise");
        assert_eq!(element, recovered);
    }

    #[test]
    fn class_group_element_from_bytes_preserves_encoding() {
        let raw = vec![0xDEu8, 0xAD, 0xBE, 0xEF];
        let element = ClassGroupElement::from_bytes(raw.clone());
        assert_eq!(element.as_bytes(), &raw[..]);
    }

    #[test]
    fn class_group_element_equality_is_byte_equality() {
        let a = ClassGroupElement::from_bytes(vec![0x01, 0x02, 0x03]);
        let b = ClassGroupElement::from_bytes(vec![0x01, 0x02, 0x03]);
        let c = ClassGroupElement::from_bytes(vec![0x01, 0x02, 0x04]);
        assert_eq!(a, b, "byte-equal encodings produce equal elements");
        assert_ne!(a, c, "byte-distinct encodings produce distinct elements");
    }

    #[test]
    fn wesolowski_proof_bcs_round_trip() {
        let proof = fixture_proof();
        let bytes = bcs::to_bytes(&proof).expect("serialise");
        let recovered: WesolowskiProof = bcs::from_bytes(&bytes).expect("deserialise");
        assert_eq!(proof, recovered);
    }

    #[test]
    fn time_lock_envelope_bcs_round_trip() {
        let envelope = fixture_envelope();
        let bytes = bcs::to_bytes(&envelope).expect("serialise");
        let recovered: TimeLockEnvelope = bcs::from_bytes(&bytes).expect("deserialise");
        assert_eq!(envelope, recovered);
    }

    #[test]
    fn time_lock_envelope_field_order_is_puzzle_ciphertext_proof() {
        // BCS encodes struct fields in declaration order. Pin the
        // wire-field order here — any future reordering of the
        // struct fields would be a consensus-breaking change and
        // must surface as a failing test.
        let envelope = TimeLockEnvelope {
            puzzle: ClassGroupElement::from_bytes(vec![0xAA]),
            ciphertext: vec![0xBB],
            well_formedness_proof: WesolowskiProof {
                pi: ClassGroupElement::from_bytes(vec![0xCC]),
            },
        };
        let bytes = bcs::to_bytes(&envelope).expect("serialise");
        // Layout:
        //   - puzzle: ULEB128(1) || [0xAA]
        //   - ciphertext: ULEB128(1) || [0xBB]
        //   - well_formedness_proof.pi: ULEB128(1) || [0xCC]
        assert_eq!(bytes, vec![0x01, 0xAA, 0x01, 0xBB, 0x01, 0xCC]);
    }

    #[test]
    fn time_lock_decryption_bcs_round_trip() {
        let decryption = fixture_decryption();
        let bytes = bcs::to_bytes(&decryption).expect("serialise");
        let recovered: TimeLockDecryption = bcs::from_bytes(&bytes).expect("deserialise");
        assert_eq!(decryption, recovered);
    }

    #[test]
    fn parameter_commitment_uses_time_lock_parameters_tag() {
        // Re-derive the parameter commitment via the documented
        // composition and confirm the helper agrees.
        let params = fixture_parameters();
        let bytes = bcs::to_bytes(&params).expect("serialise");
        let expected = crate::hash::sha3_256_tagged(&crate::domain::TIME_LOCK_PARAMETERS, &bytes);
        assert_eq!(params.parameter_commitment(), expected);
    }

    #[test]
    fn parameter_commitment_is_deterministic() {
        let params = fixture_parameters();
        assert_eq!(
            params.parameter_commitment(),
            params.parameter_commitment(),
            "parameter_commitment must be deterministic across calls"
        );
    }

    #[test]
    fn parameter_commitment_distinguishes_distinct_parameters() {
        let mut a = fixture_parameters();
        let mut b = fixture_parameters();
        b.time_parameter_t = a.time_parameter_t.wrapping_add(1);
        assert_ne!(
            a.parameter_commitment(),
            b.parameter_commitment(),
            "different T must produce different parameter commitments"
        );
        a.discriminant.push(0x00);
        assert_ne!(
            a.parameter_commitment(),
            b.parameter_commitment(),
            "different discriminant bytes must produce different commitments"
        );
    }

    #[test]
    fn parameter_commitment_is_domain_separated_from_plain_sha3() {
        // Cross-domain check: the tagged commitment must differ
        // from plain SHA3-256 of the BCS bytes. This is the
        // canonical BIP-340 tagged-hash domain-separation
        // property (§3.3.1).
        let params = fixture_parameters();
        let bytes = bcs::to_bytes(&params).expect("serialise");
        let plain = crate::hash::sha3_256_plain(&bytes);
        assert_ne!(
            params.parameter_commitment(),
            plain,
            "tagged and plain SHA3 must differ"
        );
    }

    #[test]
    fn vdf_error_display_messages_are_meaningful() {
        // Each variant must produce a non-empty, distinct error
        // message so log output and audit traces remain useful.
        let variants = [
            VdfError::MalformedEncoding,
            VdfError::ParameterMismatch,
            VdfError::ProofVerificationFailed,
            VdfError::DecryptionFailed,
        ];
        let messages: Vec<String> = variants.iter().map(ToString::to_string).collect();
        for msg in &messages {
            assert!(
                !msg.is_empty(),
                "VdfError variant produced an empty message"
            );
        }
        // All four variants must produce pairwise-distinct messages.
        for i in 0..messages.len() {
            for j in (i + 1)..messages.len() {
                assert_ne!(
                    messages[i], messages[j],
                    "VdfError variants must produce distinct messages"
                );
            }
        }
    }

    #[test]
    fn vdf_error_implements_std_error() {
        // The trait bound is checked at compile time; this test
        // pins the invariant so future refactors that drop the
        // `impl std::error::Error` surface as a test-time signal.
        fn assert_error<E: std::error::Error>() {}
        assert_error::<VdfError>();
    }

    #[test]
    fn fixture_time_parameter_t_falls_in_spec_range() {
        // §3.8.2 pins `T ∈ [2_000_000, 7_500_000]` (subject to
        // pre-mainnet calibration). The test fixture sits at the
        // lower bound; this assertion documents the range and
        // signals if the fixture is ever moved outside.
        let params = fixture_parameters();
        assert!(
            (2_000_000..=7_500_000).contains(&params.time_parameter_t),
            "fixture T must sit in the §3.8.2 calibration range"
        );
    }

    #[test]
    fn class_group_element_supports_hash_for_set_membership() {
        // Consensus uses class-group elements as keys in
        // mempool deduplication structures; the type must
        // satisfy `Hash`. Pin the property here so future
        // refactors that drop the derive surface as a test-time
        // signal.
        let mut set = std::collections::HashSet::new();
        set.insert(fixture_element(0x01));
        set.insert(fixture_element(0x02));
        set.insert(fixture_element(0x01));
        assert_eq!(set.len(), 2);
    }
}
