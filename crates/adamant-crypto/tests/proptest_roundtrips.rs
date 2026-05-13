#![allow(
    clippy::doc_markdown,
    reason = "Test file: doc comments embed math notation and crate names"
)]

//! Property-based round-trip tests for Adamant's cryptographic
//! primitives.
//!
//! Each primitive that exposes a `to_bytes` / `from_bytes` pair,
//! an `encrypt` / `decrypt` pair, or a `sign` / `verify` pair
//! gets a proptest pinning the round-trip property under
//! randomly-sampled inputs.
//!
//! Per whitepaper §3, the cryptographic primitives are
//! consensus-binding — any drift in their byte-level behaviour
//! is a hard-fork-significant change. These tests give us
//! 256-iteration sweeps over the input space catching regressions
//! that the canonical KAT vectors might miss.
//!
//! Scope: every Adamant-authored crypto surface where the byte
//! shape is consensus-pinned. Vendored upstream tests (RustCrypto
//! conformance suites, `blst` test vectors) are out-of-scope —
//! they're already covered by the upstream maintainers' own CI.
//!
//! ML-KEM-768 (§3.7) round-trips are intentionally OMITTED here
//! because the upstream `ml-kem` crate uses `rand_core` 0.10's
//! `CryptoRng` trait whereas the rest of the workspace's RNG
//! plumbing (Ed25519, BLS, this test's `TestRng`) is on
//! `rand_core` 0.6. The trait-version skew is documented in
//! `SECURITY.md` "RustCrypto ecosystem skew"; ML-KEM round-trip
//! coverage already lives inside `adamant-crypto/src/ml_kem.rs`
//! tests where the trait machinery composes natively.

use proptest::prelude::*;

use adamant_crypto::bls;
use adamant_crypto::domain;
use adamant_crypto::hash::sha3_256_tagged;
use adamant_crypto::sig_classical as ed25519;
use adamant_crypto::symmetric::{Key as SymKey, Nonce};

// ---------------------------------------------------------------
// SHA3-256 tagged hash properties
// ---------------------------------------------------------------

proptest! {
    /// Distinct inputs produce distinct outputs (with overwhelming
    /// probability — collisions are negligible on SHA3-256).
    #[test]
    fn prop_distinct_input_distinct_output(
        a in prop::collection::vec(any::<u8>(), 1..256),
        b in prop::collection::vec(any::<u8>(), 1..256),
    ) {
        prop_assume!(a != b);
        let h_a = sha3_256_tagged(&domain::OBJECT_ID, &a);
        let h_b = sha3_256_tagged(&domain::OBJECT_ID, &b);
        prop_assert_ne!(h_a, h_b);
    }

    /// Output is always exactly 32 bytes regardless of input length.
    #[test]
    fn prop_output_width_fixed_32(
        input in prop::collection::vec(any::<u8>(), 0..1024),
    ) {
        let h = sha3_256_tagged(&domain::OBJECT_ID, &input);
        prop_assert_eq!(h.len(), 32);
    }
}

// ---------------------------------------------------------------
// ChaCha20-Poly1305 AEAD (§3.5) round-trip
// ---------------------------------------------------------------

proptest! {
    /// Encrypt then decrypt produces the original plaintext.
    /// Per §3.5 the ChaCha20-Poly1305 AEAD is consensus-binding;
    /// any drift in round-trip behaviour would surface as a
    /// shielded-note or threshold-mempool decryption failure.
    #[test]
    fn prop_aead_round_trip(
        key_bytes in prop::array::uniform32(any::<u8>()),
        nonce_bytes in prop::array::uniform12(any::<u8>()),
        aad in prop::collection::vec(any::<u8>(), 0..64),
        plaintext in prop::collection::vec(any::<u8>(), 0..512),
    ) {
        let key = SymKey::from_bytes(&key_bytes);
        let nonce = Nonce(nonce_bytes);
        let ciphertext = key
            .encrypt(&nonce, &plaintext, &aad)
            .expect("encrypt");
        let recovered = key
            .decrypt(&nonce, &ciphertext, &aad)
            .expect("decrypt");
        prop_assert_eq!(plaintext, recovered);
    }

    /// AEAD authentication catches ciphertext tampering. Any
    /// single bit flip should be rejected.
    #[test]
    fn prop_aead_rejects_tampered_ciphertext(
        key_bytes in prop::array::uniform32(any::<u8>()),
        nonce_bytes in prop::array::uniform12(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..128),
        flip_byte_index in 0usize..16usize,
    ) {
        let key = SymKey::from_bytes(&key_bytes);
        let nonce = Nonce(nonce_bytes);
        let mut ciphertext = key
            .encrypt(&nonce, &plaintext, &[])
            .expect("encrypt");
        // Flip a bit in the ciphertext body.
        let idx = flip_byte_index % ciphertext.len();
        ciphertext[idx] ^= 0x01;
        let result = key.decrypt(&nonce, &ciphertext, &[]);
        prop_assert!(result.is_err(), "tampered ciphertext must fail decrypt");
    }

    /// AEAD AAD binding: changing the AAD invalidates the
    /// ciphertext authentication.
    #[test]
    fn prop_aead_aad_bound(
        key_bytes in prop::array::uniform32(any::<u8>()),
        nonce_bytes in prop::array::uniform12(any::<u8>()),
        plaintext in prop::collection::vec(any::<u8>(), 1..128),
        aad_a in prop::collection::vec(any::<u8>(), 1..32),
        aad_b in prop::collection::vec(any::<u8>(), 1..32),
    ) {
        prop_assume!(aad_a != aad_b);
        let key = SymKey::from_bytes(&key_bytes);
        let nonce = Nonce(nonce_bytes);
        let ciphertext = key
            .encrypt(&nonce, &plaintext, &aad_a)
            .expect("encrypt");
        let result = key.decrypt(&nonce, &ciphertext, &aad_b);
        prop_assert!(result.is_err(), "mismatched AAD must fail decrypt");
    }

    /// Symmetric key byte round-trip.
    #[test]
    fn prop_sym_key_byte_round_trip(
        key_bytes in prop::array::uniform32(any::<u8>()),
    ) {
        let key = SymKey::from_bytes(&key_bytes);
        prop_assert_eq!(key.to_bytes(), key_bytes);
    }
}

// ---------------------------------------------------------------
// Ed25519 (§3.4.1) sign/verify round-trip
// ---------------------------------------------------------------

proptest! {
    /// Sign then verify against the same key+message succeeds.
    #[test]
    fn prop_ed25519_sign_verify_round_trip(
        seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let sk = ed25519::SigningKey::from_seed(&seed);
        let pk = sk.verifying_key();
        let sig = sk.sign(&message);
        prop_assert!(pk.verify(&message, &sig).is_ok());
    }

    /// Verify against a different message fails.
    #[test]
    fn prop_ed25519_rejects_different_message(
        seed in prop::array::uniform32(any::<u8>()),
        m1 in prop::collection::vec(any::<u8>(), 1..128),
        m2 in prop::collection::vec(any::<u8>(), 1..128),
    ) {
        prop_assume!(m1 != m2);
        let sk = ed25519::SigningKey::from_seed(&seed);
        let pk = sk.verifying_key();
        let sig = sk.sign(&m1);
        prop_assert!(pk.verify(&m2, &sig).is_err());
    }

    /// Ed25519 VerifyingKey byte round-trip.
    #[test]
    fn prop_ed25519_verifying_key_byte_round_trip(
        seed in prop::array::uniform32(any::<u8>()),
    ) {
        let sk = ed25519::SigningKey::from_seed(&seed);
        let pk = sk.verifying_key();
        let bytes = pk.to_bytes();
        let decoded = ed25519::VerifyingKey::from_bytes(&bytes)
            .expect("ed25519 verifying key must round-trip");
        prop_assert_eq!(pk.to_bytes(), decoded.to_bytes());
    }

    /// Ed25519 Signature byte round-trip.
    #[test]
    fn prop_ed25519_signature_byte_round_trip(
        seed in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let sk = ed25519::SigningKey::from_seed(&seed);
        let sig = sk.sign(&message);
        let bytes = sig.to_bytes();
        let decoded = ed25519::Signature::from_bytes(&bytes);
        prop_assert_eq!(sig.to_bytes(), decoded.to_bytes());
    }
}

// ---------------------------------------------------------------
// BLS12-381 (§3.4.3 + §3.6) sign/verify round-trip
// ---------------------------------------------------------------

proptest! {
    /// BLS sign then verify against the same key+message succeeds.
    #[test]
    fn prop_bls_sign_verify_round_trip(
        ikm in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..256),
    ) {
        let sk = bls::SecretKey::from_ikm(&ikm)
            .expect("bls keygen must succeed with 32-byte ikm");
        let pk = sk.public_key();
        let sig = sk.sign(&message);
        prop_assert!(pk.verify(&message, &sig).is_ok());
    }

    /// BLS sign-then-verify on a different message must fail.
    #[test]
    fn prop_bls_rejects_different_message(
        ikm in prop::array::uniform32(any::<u8>()),
        m1 in prop::collection::vec(any::<u8>(), 1..128),
        m2 in prop::collection::vec(any::<u8>(), 1..128),
    ) {
        prop_assume!(m1 != m2);
        let sk = bls::SecretKey::from_ikm(&ikm).expect("keygen");
        let pk = sk.public_key();
        let sig = sk.sign(&m1);
        prop_assert!(pk.verify(&m2, &sig).is_err());
    }

    /// BLS public key byte round-trip.
    #[test]
    fn prop_bls_public_key_byte_round_trip(
        ikm in prop::array::uniform32(any::<u8>()),
    ) {
        let sk = bls::SecretKey::from_ikm(&ikm).expect("keygen");
        let pk = sk.public_key();
        let bytes = pk.to_bytes();
        let decoded = bls::PublicKey::from_bytes(&bytes)
            .expect("bls public key must round-trip");
        prop_assert_eq!(pk.to_bytes(), decoded.to_bytes());
    }

    /// BLS signature byte round-trip.
    #[test]
    fn prop_bls_signature_byte_round_trip(
        ikm in prop::array::uniform32(any::<u8>()),
        message in prop::collection::vec(any::<u8>(), 0..128),
    ) {
        let sk = bls::SecretKey::from_ikm(&ikm).expect("keygen");
        let sig = sk.sign(&message);
        let bytes = sig.to_bytes();
        let decoded = bls::Signature::from_bytes(&bytes)
            .expect("bls signature must round-trip");
        prop_assert_eq!(sig.to_bytes(), decoded.to_bytes());
    }

    /// BLS secret key byte round-trip.
    #[test]
    fn prop_bls_secret_key_byte_round_trip(
        ikm in prop::array::uniform32(any::<u8>()),
    ) {
        let sk = bls::SecretKey::from_ikm(&ikm).expect("keygen");
        let bytes = sk.to_bytes();
        let decoded = bls::SecretKey::from_bytes(&bytes)
            .expect("bls secret key must round-trip");
        prop_assert_eq!(sk.to_bytes(), decoded.to_bytes());
    }
}
