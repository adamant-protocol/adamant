//! Centralised domain-separation registry.
//!
//! Per whitepaper section 3.3.1, every consensus-critical hashing operation
//! MUST use the BIP-340 tagged-hash construction:
//!
//! ```text
//! tagged_hash_sha3(tag, input)  = SHA3-256( SHA3-256(tag) || SHA3-256(tag) || input )
//! tagged_shake(tag, input, len) = SHAKE-256( SHA3-256(tag) || SHA3-256(tag) || input, len )
//! ```
//!
//! The tag is a domain identifier of the form `b"ADAMANT-v1-<context>"` and
//! must be drawn from this registry. The 32-byte `SHA3-256(tag)` prefix is
//! computed lazily on first use of each tag and cached for the process
//! lifetime; the same prefix is shared across both SHA3-256 and SHAKE-256
//! tagged hashes.
//!
//! Per whitepaper section 3.3.1: "Adding, removing, or renaming a tag is a
//! consensus rule change and follows the procedure in section 3.10."
//!
//! # Adding a tag
//!
//! 1. Add a `pub static` entry of type [`DomainTag`] (or [`BlsDst`] for
//!    BLS hash-to-curve uses), with a doc comment naming the whitepaper
//!    section that requires it.
//! 2. Reference the constant from the using module — never inline a tag
//!    string at a use site.
//! 3. Call out the addition in the commit message; this file is part of
//!    the security audit surface.
//!
//! # Status of tags
//!
//! Whitepaper v0.1 fully names six canonical tags so far: BLS
//! hash-to-curve (section 3.4.3), threshold-encryption hash-to-curve
//! (section 3.6.1), the threshold-encryption KDF tag (section 3.6.1),
//! the account-address derivation tag (section 4.2), the
//! `ObjectId` derivation tag (section 5.1.1), and the transaction-hash
//! derivation tag (section 6.0.4). Other sections reference a
//! `domain_tag` placeholder for protocol contexts whose exact byte
//! string is to be specified when those sections are implemented:
//!
//! | Context                         | Whitepaper section | Status |
//! |---------------------------------|--------------------|--------|
//! | BLS signature hash-to-curve     | 3.4.3              | [`BLS_SIG_HASH_TO_CURVE`]. |
//! | Threshold-encryption hash-to-curve | 3.6.1           | [`BLS_TE_HASH_TO_CURVE`]. |
//! | Threshold-encryption KDF        | 3.6.1              | [`THRESHOLD_KDF`]. |
//! | Account address derivation      | 4.2                | [`ACCOUNT_ADDRESS`]. |
//! | `ObjectId` derivation           | 5.1.1              | [`OBJECT_ID`]. |
//! | Transaction-hash derivation     | 6.0.4              | [`TX_HASH`]. |
//! | Nullifier-hash (Poseidon)       | 7.1.2              | [`NULLIFIER_HASH`]. |
//! | Nullifier-key derivation        | 7.1.2              | [`NULLIFIER_KEY_DERIVATION`]. |
//! | Note metadata hash              | 7.1                | [`NOTE_METADATA_HASH`]. |
//! | Stealth-address shared secret   | 7                  | Tag string deferred to Phase 6 (`adamant-privacy`). |
//! | Memo key derivation             | 7                  | Tag string deferred to Phase 6 (`adamant-privacy`). |
//!
//! The whitepaper's worked example in section 3.3.1 anticipated the
//! [`OBJECT_ID`] tag string `b"ADAMANT-v1-object-id"`; Phase 4 makes
//! that anticipation official and the formerly test-only constant
//! collapses into the production registry.

use std::sync::OnceLock;

use sha3::{Digest, Sha3_256};

/// A registered domain-separation tag for use with the BIP-340 tagged-hash
/// construction over SHA3 (whitepaper section 3.3.1).
///
/// Instances of this type can only be constructed inside the [`crate::domain`]
/// module, which makes it impossible at the type level to call a
/// domain-separated hash function with a tag that has not been registered
/// here.
///
/// Each `DomainTag` lazily caches `SHA3-256(tag)` on first use. The cache
/// is shared across all hashes that use the tag — both
/// [`crate::hash::sha3_256_tagged`] and [`crate::hash::shake_256_tagged`]
/// use the same precomputed 32-byte prefix.
#[derive(Debug)]
pub struct DomainTag {
    bytes: &'static [u8],
    cached_prefix: OnceLock<[u8; 32]>,
}

impl DomainTag {
    /// Private constructor. Every tag MUST be declared in this module.
    /// Per whitepaper 3.3.1, "Adding, removing, or renaming a tag is a
    /// consensus rule change."
    const fn new(bytes: &'static [u8]) -> Self {
        Self {
            bytes,
            cached_prefix: OnceLock::new(),
        }
    }

    /// The raw tag bytes (without the BIP-340 prefix transformation).
    #[must_use]
    pub fn as_bytes(&self) -> &'static [u8] {
        self.bytes
    }

    /// Returns the cached `SHA3-256(tag)` prefix, computing it lazily on
    /// first call. The cache is process-lifetime — once computed, the
    /// value is reused for every subsequent tagged-hash invocation on
    /// this `DomainTag`.
    pub(crate) fn cached_prefix(&self) -> &[u8; 32] {
        self.cached_prefix.get_or_init(|| {
            let mut hasher = Sha3_256::new();
            hasher.update(self.bytes);
            hasher.finalize().into()
        })
    }
}

/// A registered hash-to-curve domain-separation tag (DST) for use with
/// BLS signatures over BLS12-381 (whitepaper section 3.4.3).
///
/// `BlsDst` is distinct from [`DomainTag`] because BLS hash-to-curve
/// tags follow the IRTF `draft-irtf-cfrg-hash-to-curve` ciphersuite-tag
/// format and are consumed by the BLS hash-to-curve operation directly,
/// not by the BIP-340 tagged-hash construction. They have no cached
/// prefix.
#[derive(Debug)]
pub struct BlsDst {
    bytes: &'static [u8],
}

impl BlsDst {
    /// Private constructor — every tag MUST be declared in this module.
    const fn new(bytes: &'static [u8]) -> Self {
        Self { bytes }
    }

    /// The raw DST bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &'static [u8] {
        self.bytes
    }
}

/// BLS signature hash-to-curve domain tag, per whitepaper section 3.4.3.
///
/// This is the IRTF `draft-irtf-cfrg-hash-to-curve` ciphersuite tag for
/// suite `BLS12381G1_XMD:SHA-256_SSWU_RO_`, with the protocol-specific
/// suffix `ADAMANT_v1`. Used as the DST for all BLS aggregate signatures
/// over G1.
pub static BLS_SIG_HASH_TO_CURVE: BlsDst =
    BlsDst::new(b"BLS_SIG_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1");

/// Threshold-encryption hash-to-curve domain tag, per whitepaper
/// section 3.6.1.
///
/// Distinct from [`BLS_SIG_HASH_TO_CURVE`] to prevent cross-protocol
/// attacks: a decryption share is computationally identical to a BLS
/// signature on the same identity under the same key share, so without
/// domain separation a value valid as a signature could be substituted
/// as a decryption share. The TE-specific suite name (`BLS_TE_…` rather
/// than `BLS_SIG_…`) cryptographically separates the two operations.
/// See whitepaper 3.6.1 "Domain separation" for the construction-level
/// rationale.
pub static BLS_TE_HASH_TO_CURVE: BlsDst =
    BlsDst::new(b"BLS_TE_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1");

/// Threshold-encryption KDF domain tag, per whitepaper section 3.6.1.
///
/// Used with the BIP-340 tagged-SHAKE-256 construction
/// ([`crate::hash::shake_256_tagged`]) to derive the 32-byte symmetric
/// key from the encapsulator's pairing-output transcript:
/// `K = tagged_shake_256(tag, serialise(GT_value) || serialise(U) || identity, 32)`.
pub static THRESHOLD_KDF: DomainTag = DomainTag::new(b"ADAMANT-v1-threshold-kdf");

/// Account-address derivation domain tag, per whitepaper section 4.2.
///
/// Used with the BIP-340 tagged-SHA3-256 construction
/// ([`crate::hash::sha3_256_tagged`]) to derive an account's 32-byte
/// address from the BCS-encoded tuple
/// `(creation_tx_hash, creator_address, index)`:
///
/// `Address = tagged_hash_sha3(tag, BCS(input))`
///
/// where `input` is the `DerivationInput` struct in `adamant-account`.
/// The BCS encoding (whitepaper section 5.1.8) makes the input byte
/// string consensus-canonical across implementations; the tagged-hash
/// construction (whitepaper 3.3.1) makes the derivation domain-separated
/// from every other protocol-level hash.
pub static ACCOUNT_ADDRESS: DomainTag = DomainTag::new(b"ADAMANT-v1-account-address");

/// `ObjectId` derivation domain tag, per whitepaper section 5.1.1.
///
/// Used with the BIP-340 tagged-SHA3-256 construction
/// ([`crate::hash::sha3_256_tagged`]) to derive an object's 32-byte
/// identifier from the BCS-encoded tuple
/// `(creation_tx_hash, creator_address, creation_index)`:
///
/// `ObjectId = tagged_hash_sha3(tag, BCS(input))`
///
/// where `input` is the `DerivationInput` struct in `adamant-state`.
/// Same composition as [`ACCOUNT_ADDRESS`] with a distinct tag and a
/// different output type — see CONTRIBUTING.md "Derivation
/// discipline" for the four invariants every protocol-level
/// identifier derivation must hold.
///
/// The byte string was anticipated by the worked example in
/// whitepaper section 3.3.1.
pub static OBJECT_ID: DomainTag = DomainTag::new(b"ADAMANT-v1-object-id");

/// Transaction-hash derivation domain tag, per whitepaper section 6.0.4.
///
/// Used with the BIP-340 tagged-SHA3-256 construction
/// ([`crate::hash::sha3_256_tagged`]) to derive a transaction's
/// 32-byte `TxHash` from the BCS-encoded `TxBody`:
///
/// `TxHash = tagged_hash_sha3(tag, BCS(body))`
///
/// The hash covers the body alone (per section 6.0.1's body /
/// auth-evidence split); auth evidence is excluded so signatures
/// can sign `BCS(body)` without circular dependency. Same
/// composition as [`ACCOUNT_ADDRESS`] and [`OBJECT_ID`] with a
/// distinct tag — see CONTRIBUTING.md "Derivation discipline" for
/// the four invariants every protocol-level identifier derivation
/// must hold.
pub static TX_HASH: DomainTag = DomainTag::new(b"ADAMANT-v1-tx-hash");

/// Note-metadata-hash domain tag, per whitepaper section 7.1.
///
/// Used with the BIP-340 tagged-SHA3-256 construction
/// ([`crate::hash::sha3_256_tagged`]) to derive the
/// `metadata_hash` input to the [Poseidon-based note-commitment
/// formula](https://docs.rs/adamant-privacy) per §7.1:
///
/// `metadata_hash = tagged_hash_sha3(tag, BCS(NoteMetadata))`
///
/// The metadata-hash is then reduced to a Pallas base field
/// element (per §3.3.3 amendment instance 31) and fed as the
/// fifth Poseidon input alongside `value`, `asset_type`,
/// `recipient`, and `randomness`. The tag-and-reduce pattern
/// keeps note-metadata's tagged-hash separate from any other
/// SHA3 use of the same byte content.
///
/// Per §3.3.1, adding/renaming domain tags is a hard fork.
/// Registered at Phase 6.1.
pub static NOTE_METADATA_HASH: DomainTag = DomainTag::new(b"ADAMANT-v1-note-metadata-hash");

/// Nullifier-hash domain tag, per whitepaper section 7.1.2.
///
/// Used as the first field-element input to the Poseidon
/// nullifier construction:
///
/// `nullifier = Poseidon(domain_tag || nullifier_key || note_commitment || position_in_tree)`
///
/// The byte tag is converted to a Pallas-base-field element via
/// `tagged_hash_sha3` followed by the standard reduction
/// (`FieldBytes::from_bytes_reduced`); the field-element value is
/// uniquely determined by this byte string. Distinct from
/// [`NULLIFIER_KEY_DERIVATION`] to keep the inner and outer
/// Poseidon hashes domain-separated.
///
/// Per §3.3.1, adding/renaming domain tags is a hard fork.
/// Registered at Phase 6.2.
pub static NULLIFIER_HASH: DomainTag = DomainTag::new(b"ADAMANT-v1-nullifier-hash");

/// Nullifier-key derivation domain tag, per whitepaper section 7.1.2.
///
/// Used as the first field-element input to the inner Poseidon
/// derivation that produces the nullifier-key from the spending
/// key:
///
/// `nullifier_key = Poseidon(domain || spending_key)`
///
/// Distinct from [`NULLIFIER_HASH`] so a cross-domain attack —
/// substituting a nullifier output as a nullifier-key, or vice
/// versa — is rejected by domain mismatch.
///
/// Per §3.3.1, adding/renaming domain tags is a hard fork.
/// Registered at Phase 6.2.
pub static NULLIFIER_KEY_DERIVATION: DomainTag =
    DomainTag::new(b"ADAMANT-v1-nullifier-key-derivation");

/// Stealth-address shared-scalar domain tag, per whitepaper section 7.2.2.
///
/// Used in `s = HashToScalar(ss || domain_tag)` where `ss` is the
/// 32-byte ML-KEM shared secret and `s` is a Pallas scalar
/// (post-amendment instance 32). The byte tag is one component of
/// the input to the SHA3-derived scalar hashing; the resulting
/// scalar `s` is then used in `P = pk_s + s · G` to produce the
/// one-time stealth address.
///
/// Per §3.3.1, adding/renaming domain tags is a hard fork.
/// Registered at Phase 6.4.
pub static STEALTH_SHARED_SCALAR: DomainTag =
    DomainTag::new(b"ADAMANT-v1-stealth-shared-scalar");

/// Master-seed → spending-key derivation domain tag, per
/// whitepaper section 7.4.1.
///
/// Used as the salt for HKDF-SHA3 derivation of the spending
/// scalar from a 32-byte master seed:
///
/// `tagged_shake_256(MASTER_SPENDING_KEY, master_seed, 64)` →
/// reduce to `pallas::Scalar`.
///
/// Distinct from [`MASTER_VIEWING_KEY`] so the same master seed
/// cannot collide spending- and viewing-key material under any
/// single derivation. Per §3.3.1, adding/renaming domain tags is
/// a hard fork. Registered at Phase 6.5.
pub static MASTER_SPENDING_KEY: DomainTag = DomainTag::new(b"ADAMANT-v1-master-spending-key");

/// Master-seed → viewing-keypair-seed derivation domain tag, per
/// whitepaper section 7.4.1.
///
/// Used to derive the 64-byte ML-KEM-768 keypair seed
/// (`sk_v_kem_seed` per §7.2.2) from the master seed:
///
/// `tagged_shake_256(MASTER_VIEWING_KEY, master_seed, 64)` →
/// `ML-KEM-768.KeyGen(seed)`.
///
/// Distinct from [`MASTER_SPENDING_KEY`] so spending and viewing
/// material derived from the same master seed are
/// cryptographically separated. Per §3.3.1, adding/renaming
/// domain tags is a hard fork. Registered at Phase 6.5.
pub static MASTER_VIEWING_KEY: DomainTag = DomainTag::new(b"ADAMANT-v1-master-viewing-key");

/// Sub-view-key HKDF-SHA3 salt domain tag, per whitepaper
/// section 7.4.2 amendment (`domain_tag_subview`).
///
/// Used as the salt input to HKDF-SHA3-256 for sub-view-key
/// derivation:
///
/// ```text
/// sub_seed_S = HKDF-SHA3(
///     salt = SUBVIEW_DERIVE_tag,
///     ikm  = sk_v_kem_seed,
///     info = BCS(S),
///     L    = 64
/// )
/// ```
///
/// The 64-byte output is the ML-KEM-768.KeyGen seed for the
/// scope-S sub-view-keypair. Per §3.3.1, adding/renaming domain
/// tags is a hard fork. Registered at Phase 6.5.
pub static SUBVIEW_DERIVE: DomainTag = DomainTag::new(b"ADAMANT-v1-subview-derive");

/// Stealth-address view-tag domain tag, per whitepaper section 7.2.4.
///
/// Used in `view_tag = SHA3_256(ss || tag_domain)[0]` where `ss`
/// is the 32-byte ML-KEM shared secret. The view tag is the
/// first byte of the tagged SHA3-256 of the shared secret;
/// recipients use it as a fast filter when scanning the chain
/// (rejecting ~255/256 of unrelated notes before computing the
/// full stealth-address derivation).
///
/// Distinct from [`STEALTH_SHARED_SCALAR`] so the view-tag and
/// the shared-scalar derivations cannot collide. Per §3.3.1,
/// adding/renaming domain tags is a hard fork. Registered at
/// Phase 6.4.
pub static STEALTH_VIEW_TAG: DomainTag = DomainTag::new(b"ADAMANT-v1-stealth-view-tag");

/// Test-only domain tags. These do not enter the consensus tag set; they
/// exist only to exercise tagged-hash composition in unit tests and
/// test-vector regressions.
///
/// **These are deliberately test-only tags for verifying
/// domain-separation invariants; they MUST NOT be promoted to
/// production tags.** For tags awaiting Phase-N promotion, see the
/// deferred-tags status table at the top of this file.
#[cfg(test)]
pub(crate) mod test_tags {
    use super::DomainTag;

    /// Generic test tag A — used to verify domain-separation, cache
    /// behaviour, and construction matching against the spec formula.
    pub(crate) static TAG_A: DomainTag = DomainTag::new(b"ADAMANT-v1-test-tag-a");

    /// Generic test tag B — used together with [`TAG_A`] to verify that
    /// distinct tags produce distinct outputs for the same input.
    pub(crate) static TAG_B: DomainTag = DomainTag::new(b"ADAMANT-v1-test-tag-b");
}
