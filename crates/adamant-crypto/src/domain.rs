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
//! Whitepaper v0.1 fully names exactly one canonical tag, for BLS
//! hash-to-curve (section 3.4.3). Other sections reference a `domain_tag`
//! placeholder for protocol contexts whose exact byte string is to be
//! specified when those sections are implemented:
//!
//! | Context                         | Whitepaper section | Status |
//! |---------------------------------|--------------------|--------|
//! | Account address derivation      | 4                  | Tag string deferred to Phase 3 (`adamant-account`). |
//! | `ObjectId` derivation           | 5                  | Tag string deferred to Phase 4 (`adamant-state`). |
//! | Nullifier (Poseidon, in-circuit)| 7                  | Tag string deferred to Phase 6 (`adamant-privacy`). |
//! | Stealth-address shared secret   | 7                  | Tag string deferred to Phase 6 (`adamant-privacy`). |
//! | Memo key derivation             | 7                  | Tag string deferred to Phase 6 (`adamant-privacy`). |
//!
//! The whitepaper's worked example in section 3.3.1 uses the illustrative
//! string `b"ADAMANT-v1-object-id"`. That string is exposed only to tests
//! (see `test_tags::WORKED_EXAMPLE_OBJECT_ID` below) until Phase 4 makes
//! the formal `ObjectId` tag decision.

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
    ///
    /// In non-test builds at this point in Phase 1, the only callers are
    /// the `#[cfg(test)] test_tags` static block — production tags
    /// (account, object-id, nullifier, …) arrive in later phases. The
    /// dead-code warning is therefore suppressed here; once Phase 3 or
    /// Phase 4 lands a non-test `DomainTag` static, this attribute can
    /// be removed.
    #[cfg_attr(not(test), allow(dead_code))]
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

/// Test-only domain tags. These do not enter the consensus tag set; they
/// exist only to exercise tagged-hash composition in unit tests and
/// test-vector regressions.
#[cfg(test)]
pub(crate) mod test_tags {
    use super::DomainTag;

    /// The illustrative tag from the worked example in whitepaper section
    /// 3.3.1. Used for the worked-example regression test. The actual
    /// `ObjectId` derivation tag (section 5) is decided in Phase 4 and
    /// may or may not equal this byte string.
    pub(crate) static WORKED_EXAMPLE_OBJECT_ID: DomainTag = DomainTag::new(b"ADAMANT-v1-object-id");

    /// Generic test tag A — used to verify domain-separation, cache
    /// behaviour, and construction matching against the spec formula.
    pub(crate) static TAG_A: DomainTag = DomainTag::new(b"ADAMANT-v1-test-tag-a");

    /// Generic test tag B — used together with [`TAG_A`] to verify that
    /// distinct tags produce distinct outputs for the same input.
    pub(crate) static TAG_B: DomainTag = DomainTag::new(b"ADAMANT-v1-test-tag-b");
}
