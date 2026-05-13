//! DAG vertex structure per whitepaper §8.3.1.
//!
//! A **vertex** is the unit of validator participation per
//! round. Each active validator produces exactly one vertex per
//! round. The DAG grows in layers: round N+1 vertices reference
//! at least `quorum_threshold(active_set_size)` parents from
//! round N (§8.3.1 / §8.3.2).
//!
//! # Vertex anatomy (§8.3.1 verbatim)
//!
//! ```text
//! Vertex {
//!     author:           ValidatorId,
//!     round:            u64,
//!     parents:          Vec<VertexId>,    // 2/3+1 of prior round
//!     transactions:     Vec<Transaction>, // mempool batch
//!     threshold_shares: Vec<DecryptionShare>,
//!     proof_witness:    PartialProofWitness,
//!     signature:        BLSSignature,
//! }
//! ```
//!
//! # `VertexId` derivation
//!
//! `VertexId = sha3_256_tagged(VERTEX_ID, BCS(UnsignedVertex))`
//! where `UnsignedVertex` is the vertex body without the
//! signature. This is the standard "id-from-body, signature-
//! over-id" pattern: the id is stable before signing, and the
//! signature signs the id. Verifiers re-derive the id from the
//! body and check the signature against it.
//!
//! # Wire-format opacity
//!
//! At the consensus layer, vertex payloads carried in
//! `transactions`, `threshold_shares`, and `proof_witness` are
//! treated as **opaque bytes**:
//!
//! - `TransactionEnvelope` wraps a BCS-encoded
//!   `adamant_vm::Transaction` (or a §8.4-encrypted variant
//!   while the mempool runs in time-lock / threshold regime).
//!   Phase 7.3 doesn't introspect the inner bytes; that
//!   happens at Phase 5/6.x execution time downstream of the
//!   commit-wave decision.
//! - `DecryptionShare` wraps a BLS / threshold-cryptography
//!   share. Full structure lands at Phase 7.6 (threshold
//!   mempool integration).
//! - `PartialProofWitness` wraps the validator's contribution
//!   to the per-epoch recursive proof per §8.5. Full structure
//!   lands at Phase 7.7 alongside DAG-BFT integration with the
//!   adamant-privacy recursive accumulator.
//!
//! This opacity keeps Phase 7.3 free of a dependency on
//! `adamant-vm`, `adamant-privacy`, or any other Phase 5–6
//! crate — consistent with the layered-architecture posture in
//! CLAUDE.md §14: consensus shouldn't structurally depend on
//! the VM or the privacy layer for wire-format compatibility.
//!
//! # Parent-quorum invariant
//!
//! Per §8.3.1: "Each vertex must reference at least 2/3+1
//! vertices from the previous round." [`Vertex::has_quorum`]
//! computes this check against an active-set size; Phase 7.7
//! wires the invariant into consensus validation when the
//! DAG-BFT core lands.
//!
//! # Phase 7.3 scope
//!
//! - Data types: `VertexId`, `Vertex`, `UnsignedVertex`,
//!   `TransactionEnvelope`, `DecryptionShare`,
//!   `PartialProofWitness`, `VertexSignature`.
//! - Id derivation per §8.3.1.
//! - Parent-quorum predicate per §8.3.1.
//! - `VertexBuilder` ergonomic construction.
//!
//! Phase 7.4 (consensus VRF) consumes `VertexId` for anchor
//! election. Phase 7.7 (DAG-BFT core) wires the validation
//! invariants into the consensus path. Phase 7.6 (threshold
//! mempool) populates `decryption_shares`. Phase 7.10
//! (slashing) wires equivocation detection (two distinct
//! vertices with the same `(author, round)`) to the §8.1.5
//! `SlashOffence::Equivocation` slashing path.

use adamant_crypto::bls::SIGNATURE_BYTES as BLS_SIGNATURE_BYTES_CONST;
use adamant_crypto::{domain, hash::sha3_256_tagged};
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use crate::epoch::RoundNumber;
use crate::identity::ValidatorId;
use crate::schedule::quorum_threshold;

/// Byte width of a BLS12-381 G1-compressed signature per IETF /
/// §3.4.3. Re-export of `adamant_crypto::bls::SIGNATURE_BYTES`.
pub const BLS_SIGNATURE_BYTES: usize = BLS_SIGNATURE_BYTES_CONST;

/// Byte width of a [`VertexId`].
pub const VERTEX_ID_BYTES: usize = 32;

// ---------------------------------------------------------------
// VertexId
// ---------------------------------------------------------------

/// Content-derived 32-byte DAG-vertex identifier per §8.3.1.
///
/// Computed as `sha3_256_tagged(VERTEX_ID, BCS(UnsignedVertex))`.
/// The id is derived from the *unsigned* body so it's stable
/// before signing; the vertex's BLS signature signs the id.
///
/// Two vertices with identical bodies produce identical ids —
/// by construction. This is the basis of equivocation detection
/// per §8.1.5: a validator who produces two distinct vertices
/// with the same `(author, round)` produces two different
/// `VertexId`s (because the body diverges in some field), and
/// any party submitting both as evidence triggers the §8.1.5
/// `Equivocation` slashing.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize, Ord, PartialOrd)]
pub struct VertexId([u8; VERTEX_ID_BYTES]);

impl VertexId {
    /// Construct from raw 32-byte material. Normally callers
    /// derive a `VertexId` from a vertex body via
    /// [`UnsignedVertex::derive_id`]; this constructor is for
    /// parsing on-chain values and test fixtures.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; VERTEX_ID_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 32-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; VERTEX_ID_BYTES] {
        self.0
    }

    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; VERTEX_ID_BYTES] {
        &self.0
    }
}

impl core::fmt::Debug for VertexId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VertexId(0x")?;
        for b in &self.0 {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

// ---------------------------------------------------------------
// Vertex payload envelopes
// ---------------------------------------------------------------

/// Opaque wrapper around a mempool transaction.
///
/// At the consensus layer, transactions are bytes-on-the-wire:
/// either a BCS-encoded `adamant_vm::Transaction` (post-
/// threshold-decryption) or a §8.4 encrypted-mempool ciphertext
/// (pre-decryption, in threshold or time-lock regime). Phase
/// 7.3 doesn't introspect the inner bytes; that happens at
/// execution time downstream of the §8.3.3 commit decision.
///
/// Keeping transactions opaque at the consensus layer lets
/// `adamant-consensus` stay free of `adamant-vm` and
/// `adamant-privacy` dependencies — consistent with the
/// layered-architecture posture in CLAUDE.md §14.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct TransactionEnvelope {
    /// Raw transaction bytes. BCS-encoded `adamant_vm::Transaction`
    /// in clear-text mempool, or §8.4 ciphertext otherwise.
    pub bytes: Vec<u8>,
}

impl TransactionEnvelope {
    /// Wrap raw bytes as a [`TransactionEnvelope`].
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the byte buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// Opaque wrapper around a threshold-decryption share per §8.4.3.
///
/// Validators publish decryption shares for previously-encrypted
/// transactions; when 2/3+1 valid shares are collected, the
/// ciphertext decrypts. Phase 7.6 (threshold mempool
/// integration) ships the full BLS-based share structure;
/// Phase 7.3 treats shares as opaque bytes.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct DecryptionShare {
    /// Raw share bytes. Phase 7.6 pins the inner structure as a
    /// BLS-pairing-derived value over the encrypted-mempool
    /// shared-secret KEM (§3.6 threshold encryption +
    /// `adamant_crypto::threshold`).
    pub bytes: Vec<u8>,
}

impl DecryptionShare {
    /// Wrap raw bytes as a [`DecryptionShare`].
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

/// Opaque wrapper around a validator's partial contribution to
/// the per-epoch recursive proof per §8.5.
///
/// Each vertex carries a partial witness; at the epoch boundary
/// (§8.5.2) the witnesses fold into the recursive accumulator
/// (Phase 6.9b's `EpochAccumulator`). Phase 7.7 (DAG-BFT core)
/// wires the fold into consensus; Phase 7.3 treats the witness
/// as opaque bytes.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct PartialProofWitness {
    /// Raw witness bytes. Phase 7.7 pins the inner structure
    /// as a partial Halo 2 verification state per
    /// `adamant_halo2::recursion::RecursiveAccumulator` /
    /// `adamant_privacy::epoch_recursion::fold_epoch`.
    pub bytes: Vec<u8>,
}

impl PartialProofWitness {
    /// Wrap raw bytes as a [`PartialProofWitness`].
    #[must_use]
    pub const fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the raw bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Empty witness, for tests and for genesis-round vertices
    /// (which have nothing to fold into the recursion).
    #[must_use]
    pub const fn empty() -> Self {
        Self { bytes: Vec::new() }
    }
}

/// BLS12-381 G1-compressed vertex signature per §8.3.1.
///
/// Signs `VertexId` (i.e., signs the body's tagged-hash).
/// Verifiers re-derive the id from the unsigned body and check
/// the signature against the author's BLS public key from
/// [`crate::ValidatorPublicKeys::bls_public_key`].
#[derive(Clone, Copy, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct VertexSignature(#[serde(with = "BigArray")] [u8; BLS_SIGNATURE_BYTES]);

impl VertexSignature {
    /// Construct from raw 48-byte material.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; BLS_SIGNATURE_BYTES]) -> Self {
        Self(bytes)
    }

    /// Canonical 48-byte encoding.
    #[must_use]
    pub const fn to_bytes(self) -> [u8; BLS_SIGNATURE_BYTES] {
        self.0
    }

    /// Borrow the underlying byte array.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; BLS_SIGNATURE_BYTES] {
        &self.0
    }

    /// All-zeros placeholder signature, for test fixtures + the
    /// `VertexBuilder` pre-signing path.
    #[must_use]
    pub const fn placeholder() -> Self {
        Self([0u8; BLS_SIGNATURE_BYTES])
    }
}

impl core::fmt::Debug for VertexSignature {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "VertexSignature(0x")?;
        // Print first 8 + last 8 bytes for diagnostic
        // readability; full 48 bytes is too wide.
        for b in &self.0[..8] {
            write!(f, "{b:02x}")?;
        }
        write!(f, "..")?;
        for b in &self.0[40..] {
            write!(f, "{b:02x}")?;
        }
        write!(f, ")")
    }
}

// ---------------------------------------------------------------
// UnsignedVertex + Vertex
// ---------------------------------------------------------------

/// The unsigned vertex body per §8.3.1.
///
/// This is what [`VertexId`] hashes over. The full
/// [`Vertex`] = `UnsignedVertex + VertexSignature`, with the
/// signature signing the unsigned body's tagged-hash.
///
/// # Field declaration order is consensus-binding
///
/// Per §5.1.8 BCS canonicality, reordering fields is a hard
/// fork. The order chosen here matches §8.3.1 verbatim:
/// author → round → parents → transactions → threshold_shares
/// → proof_witness.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct UnsignedVertex {
    /// Validator that produced this vertex per §8.3.1.
    pub author: ValidatorId,
    /// Round in which this vertex was produced per §8.3.2.
    pub round: RoundNumber,
    /// Parent vertices from round `round - 1`. Must satisfy
    /// the §8.3.1 quorum requirement (`>= quorum_threshold(N)`
    /// where N is the active-set size at this round).
    pub parents: Vec<VertexId>,
    /// Mempool transactions included in this vertex.
    /// Bytes-on-the-wire: BCS-encoded `Transaction`s or §8.4
    /// encrypted-mempool ciphertexts.
    pub transactions: Vec<TransactionEnvelope>,
    /// Threshold-decryption shares published by this validator
    /// for previously-encrypted transactions per §8.4.3.
    pub threshold_shares: Vec<DecryptionShare>,
    /// This validator's partial contribution to the per-epoch
    /// recursive proof per §8.5.
    pub proof_witness: PartialProofWitness,
}

impl UnsignedVertex {
    /// Construct an unsigned vertex from its components.
    #[must_use]
    pub fn new(
        author: ValidatorId,
        round: RoundNumber,
        parents: Vec<VertexId>,
        transactions: Vec<TransactionEnvelope>,
        threshold_shares: Vec<DecryptionShare>,
        proof_witness: PartialProofWitness,
    ) -> Self {
        Self {
            author,
            round,
            parents,
            transactions,
            threshold_shares,
            proof_witness,
        }
    }

    /// Derive this vertex's [`VertexId`] per §8.3.1:
    /// `sha3_256_tagged(VERTEX_ID, BCS(self))`.
    ///
    /// Deterministic; two `UnsignedVertex` values with
    /// identical bytes produce identical ids.
    ///
    /// # Panics
    ///
    /// Panics only if BCS serialisation fails, which cannot
    /// happen for this struct's plain-data shape (no custom
    /// serialisers, no `Result`-returning serde paths).
    #[must_use]
    pub fn derive_id(&self) -> VertexId {
        let bcs_bytes =
            bcs::to_bytes(self).expect("UnsignedVertex is BCS-serialisable by construction");
        let hash = sha3_256_tagged(&domain::VERTEX_ID, &bcs_bytes);
        VertexId::from_bytes(hash)
    }

    /// Whether this vertex's parent set satisfies the §8.3.1
    /// quorum requirement (`parents.len() >= quorum_threshold(active_set_size)`).
    ///
    /// Genesis-round vertices (`round == 0`) are exempt from
    /// the quorum requirement — they reference the genesis
    /// state directly per §8.3.2 ("At round 1, validators
    /// broadcast vertices referencing the genesis state").
    /// Round-0 vertices may have an empty `parents` set.
    ///
    /// Phase 7.7 (DAG-BFT consensus core) wires this check
    /// into the actual vertex-validation path.
    #[must_use]
    pub fn has_quorum(&self, active_set_size: usize) -> bool {
        if self.round == RoundNumber::ZERO {
            return true;
        }
        self.parents.len() >= quorum_threshold(active_set_size)
    }

    /// Whether all parent ids in this vertex are distinct. A
    /// vertex with a duplicated parent id violates the §8.3.1
    /// "Vec<VertexId>" set-semantics intent (the parents form a
    /// set, not a multiset).
    #[must_use]
    pub fn parents_are_distinct(&self) -> bool {
        let mut sorted: Vec<&VertexId> = self.parents.iter().collect();
        sorted.sort();
        sorted.windows(2).all(|w| w[0] != w[1])
    }
}

/// A complete DAG vertex per §8.3.1: the unsigned body plus
/// the author's BLS signature over the vertex id.
///
/// Wire format: BCS-encoded `(UnsignedVertex, VertexSignature)`.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Vertex {
    /// The unsigned body — author / round / parents / payload /
    /// threshold shares / proof witness.
    pub body: UnsignedVertex,
    /// BLS12-381 signature over `body.derive_id()` per §8.3.1.
    /// Phase 7.3 doesn't verify; verification lands at Phase
    /// 7.7 DAG-BFT integration using the author's BLS public
    /// key from [`crate::ValidatorPublicKeys`].
    pub signature: VertexSignature,
}

impl Vertex {
    /// Construct a signed vertex from a body + signature.
    /// Callers should normally use [`VertexBuilder`] or
    /// [`UnsignedVertex::derive_id`] + signing path.
    #[must_use]
    pub const fn new(body: UnsignedVertex, signature: VertexSignature) -> Self {
        Self { body, signature }
    }

    /// This vertex's [`VertexId`] (re-derived from `body`).
    #[must_use]
    pub fn id(&self) -> VertexId {
        self.body.derive_id()
    }

    /// Convenience accessor for `body.author`.
    #[must_use]
    pub fn author(&self) -> ValidatorId {
        self.body.author
    }

    /// Convenience accessor for `body.round`.
    #[must_use]
    pub fn round(&self) -> RoundNumber {
        self.body.round
    }

    /// Convenience accessor for `body.parents`.
    #[must_use]
    pub fn parents(&self) -> &[VertexId] {
        &self.body.parents
    }

    /// Forwards to [`UnsignedVertex::has_quorum`].
    #[must_use]
    pub fn has_quorum(&self, active_set_size: usize) -> bool {
        self.body.has_quorum(active_set_size)
    }

    /// Forwards to [`UnsignedVertex::parents_are_distinct`].
    /// Convenience accessor for downstream consensus code that
    /// holds a `Vertex` rather than the bare body.
    #[must_use]
    pub fn parents_are_distinct(&self) -> bool {
        self.body.parents_are_distinct()
    }

    /// The vertex's unsigned body. Exposed for the Phase 7.7+
    /// consensus path, which inspects body-level fields beyond
    /// the convenience accessors above (e.g., `transactions`,
    /// `threshold_shares`, `proof_witness`).
    #[must_use]
    pub const fn body(&self) -> &UnsignedVertex {
        &self.body
    }

    /// The vertex's BLS signature. Exposed for the Phase 7.7+
    /// DAG-state insertion path, which BLS-verifies the
    /// signature against the author's public key.
    #[must_use]
    pub const fn signature(&self) -> &VertexSignature {
        &self.signature
    }
}

// ---------------------------------------------------------------
// VertexBuilder — ergonomic construction
// ---------------------------------------------------------------

/// Builder pattern for constructing vertices per §8.3.1.
///
/// Typical use:
///
/// ```ignore
/// let vertex = VertexBuilder::new(author, round)
///     .add_parent(parent_id_1)
///     .add_parent(parent_id_2)
///     .add_transaction(tx_envelope)
///     .add_threshold_share(share)
///     .with_proof_witness(witness)
///     .with_signature(signature)
///     .build();
/// ```
///
/// The builder doesn't validate parent quorum or signature
/// correctness — it's a construction helper, not a validator.
/// Validation lands at the Phase 7.7 DAG-BFT consensus path.
#[derive(Clone, Debug)]
pub struct VertexBuilder {
    author: ValidatorId,
    round: RoundNumber,
    parents: Vec<VertexId>,
    transactions: Vec<TransactionEnvelope>,
    threshold_shares: Vec<DecryptionShare>,
    proof_witness: PartialProofWitness,
    signature: Option<VertexSignature>,
}

impl VertexBuilder {
    /// Start a new builder for a vertex by `author` at `round`.
    #[must_use]
    pub fn new(author: ValidatorId, round: RoundNumber) -> Self {
        Self {
            author,
            round,
            parents: Vec::new(),
            transactions: Vec::new(),
            threshold_shares: Vec::new(),
            proof_witness: PartialProofWitness::empty(),
            signature: None,
        }
    }

    /// Append a parent vertex id.
    #[must_use]
    pub fn add_parent(mut self, parent: VertexId) -> Self {
        self.parents.push(parent);
        self
    }

    /// Set the parent set (overwrites any previously-added
    /// parents).
    #[must_use]
    pub fn with_parents(mut self, parents: Vec<VertexId>) -> Self {
        self.parents = parents;
        self
    }

    /// Append a transaction envelope to the payload.
    #[must_use]
    pub fn add_transaction(mut self, tx: TransactionEnvelope) -> Self {
        self.transactions.push(tx);
        self
    }

    /// Append a threshold-decryption share.
    #[must_use]
    pub fn add_threshold_share(mut self, share: DecryptionShare) -> Self {
        self.threshold_shares.push(share);
        self
    }

    /// Set the partial proof witness.
    #[must_use]
    pub fn with_proof_witness(mut self, witness: PartialProofWitness) -> Self {
        self.proof_witness = witness;
        self
    }

    /// Set the vertex signature. Required for [`Self::build`].
    #[must_use]
    pub fn with_signature(mut self, signature: VertexSignature) -> Self {
        self.signature = Some(signature);
        self
    }

    /// Build the unsigned vertex body. Useful for callers that
    /// want to derive the id (via `UnsignedVertex::derive_id`)
    /// then sign it externally before assembling the final
    /// [`Vertex`].
    #[must_use]
    pub fn build_unsigned(self) -> UnsignedVertex {
        UnsignedVertex::new(
            self.author,
            self.round,
            self.parents,
            self.transactions,
            self.threshold_shares,
            self.proof_witness,
        )
    }

    /// Build the complete signed vertex. Requires
    /// [`Self::with_signature`] to have been called.
    ///
    /// # Panics
    ///
    /// Panics if `with_signature` was never called.
    #[must_use]
    pub fn build(self) -> Vertex {
        let signature = self
            .signature
            .expect("VertexBuilder::build requires with_signature() to have been called");
        let body = UnsignedVertex::new(
            self.author,
            self.round,
            self.parents,
            self.transactions,
            self.threshold_shares,
            self.proof_witness,
        );
        Vertex::new(body, signature)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vid(byte: u8) -> ValidatorId {
        ValidatorId::from_bytes([byte; 32])
    }

    fn vxid(byte: u8) -> VertexId {
        VertexId::from_bytes([byte; VERTEX_ID_BYTES])
    }

    fn fixed_unsigned() -> UnsignedVertex {
        UnsignedVertex::new(
            vid(0x11),
            RoundNumber::new(5),
            vec![vxid(0xA1), vxid(0xA2), vxid(0xA3)],
            vec![TransactionEnvelope::new(vec![0xDE, 0xAD, 0xBE, 0xEF])],
            vec![DecryptionShare::new(vec![0xCA, 0xFE])],
            PartialProofWitness::new(vec![0x42; 16]),
        )
    }

    // ---------- byte-width pins ----------

    #[test]
    fn vertex_id_width_pinned() {
        assert_eq!(VERTEX_ID_BYTES, 32);
    }

    #[test]
    fn bls_signature_width_pinned() {
        assert_eq!(BLS_SIGNATURE_BYTES, 48);
    }

    // ---------- VertexId ----------

    #[test]
    fn vertex_id_bcs_round_trip() {
        let id = vxid(0x77);
        let bytes = bcs::to_bytes(&id).unwrap();
        let decoded: VertexId = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(id, decoded);
        assert_eq!(bytes.len(), VERTEX_ID_BYTES);
    }

    #[test]
    fn vertex_id_debug_hex() {
        let id = vxid(0xAB);
        let s = format!("{id:?}");
        assert!(s.starts_with("VertexId(0x"));
        assert!(s.contains("ab"));
    }

    // ---------- UnsignedVertex::derive_id ----------

    #[test]
    fn derive_id_deterministic() {
        let v = fixed_unsigned();
        assert_eq!(v.derive_id(), v.derive_id());
    }

    #[test]
    fn derive_id_changes_with_any_field_byte() {
        let v1 = fixed_unsigned();
        let mut v2 = v1.clone();
        v2.round = RoundNumber::new(6);
        assert_ne!(v1.derive_id(), v2.derive_id());

        let mut v3 = v1.clone();
        v3.author = vid(0x12);
        assert_ne!(v1.derive_id(), v3.derive_id());

        let mut v4 = v1.clone();
        v4.parents.push(vxid(0xA4));
        assert_ne!(v1.derive_id(), v4.derive_id());

        let mut v5 = v1.clone();
        v5.transactions[0].bytes.push(0x00);
        assert_ne!(v1.derive_id(), v5.derive_id());
    }

    /// Pin: id derivation uses the `VERTEX_ID` domain tag, not
    /// any other tag.
    #[test]
    fn derive_id_uses_vertex_id_domain_tag() {
        let v = fixed_unsigned();
        let bcs_bytes = bcs::to_bytes(&v).unwrap();
        let with_vertex_tag = sha3_256_tagged(&domain::VERTEX_ID, &bcs_bytes);
        let with_validator_tag = sha3_256_tagged(&domain::VALIDATOR_ID, &bcs_bytes);
        assert_ne!(with_vertex_tag, with_validator_tag);
        assert_eq!(v.derive_id().to_bytes(), with_vertex_tag);
    }

    /// Known-answer regression vector pinning the canonical
    /// `VertexId` derivation wire format under fixed inputs
    /// per the CONTRIBUTING.md "Derivation discipline" rule
    /// (registered tag + BCS canonical input + tagged-SHA3
    /// composition + KAT regression vector).
    ///
    /// # Inputs (matches [`fixed_unsigned`] above)
    ///
    /// - `author` = `ValidatorId([0x11; 32])`
    /// - `round` = `5`
    /// - `parents` = `[VertexId([0xA1; 32]), VertexId([0xA2; 32]), VertexId([0xA3; 32])]`
    /// - `transactions` = `[TransactionEnvelope { bytes: vec![0xDE, 0xAD, 0xBE, 0xEF] }]`
    /// - `threshold_shares` = `[DecryptionShare { bytes: vec![0xCA, 0xFE] }]`
    /// - `proof_witness` = `PartialProofWitness { bytes: vec![0x42; 16] }`
    ///
    /// # Computation a reviewer can verify by hand
    ///
    /// 1. BCS-encode the `UnsignedVertex` in field order
    ///    (`author || round || parents || transactions ||
    ///    threshold_shares || proof_witness`). BCS uses LEB128
    ///    for Vec length prefixes.
    /// 2. Compute `prefix = SHA3-256(b"ADAMANT-v1-vertex-id")`.
    /// 3. Compute `VertexId = SHA3-256(prefix || prefix || BCS_bytes)`.
    ///
    /// The expected bytes were generated by running this
    /// derivation once and committing the output. A different
    /// result from the same inputs would indicate the wire
    /// format has drifted (consensus-breaking).
    #[test]
    fn derive_id_known_answer_vector() {
        let v = fixed_unsigned();
        let actual = v.derive_id();
        // Generated by running this test once with the expected
        // value as `[0u8; 32]`, capturing the actual output,
        // and pinning it as the regression anchor.
        let expected = VertexId::from_bytes(hex_decode_32(
            "23cd625b000d7f61aacddecdb7c802c905ea6c086bdb3252b269d63fa63a41dd",
        ));
        assert_eq!(
            actual, expected,
            "VertexId derivation regression — input is the fixed_unsigned() fixture; \
             if this assertion fails the protocol's VertexId wire format has drifted, \
             investigate before changing the expected bytes"
        );
    }

    /// Decode a 64-character hex string into a 32-byte array
    /// for KAT fixtures. Test-only helper.
    fn hex_decode_32(s: &str) -> [u8; 32] {
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

    // ---------- has_quorum ----------

    /// Per §8.3.1: "Each vertex must reference at least 2/3+1
    /// vertices from the previous round." Pin against canonical
    /// active-set sizes.
    #[test]
    fn has_quorum_pin_at_active_set_sizes() {
        // n=7 → quorum=5. Vertex with 4 parents fails; 5 passes.
        let mut v = fixed_unsigned();
        v.parents = vec![vxid(1), vxid(2), vxid(3), vxid(4)];
        assert!(!v.has_quorum(7));
        v.parents.push(vxid(5));
        assert!(v.has_quorum(7));

        // n=15 → quorum=11.
        v.parents = (0..10).map(vxid).collect();
        assert!(!v.has_quorum(15));
        v.parents.push(vxid(11));
        assert!(v.has_quorum(15));

        // n=75 → quorum=51.
        v.parents = (0..50).map(vxid).collect();
        assert!(!v.has_quorum(75));
        v.parents = (0..51).map(vxid).collect();
        assert!(v.has_quorum(75));
    }

    /// Round-0 (genesis-round) vertices are exempt per §8.3.2
    /// ("At round 1, validators broadcast vertices referencing
    /// the genesis state"). Treat round=0 as the chain anchor
    /// with no required parents.
    #[test]
    fn has_quorum_genesis_round_exempt() {
        let v = UnsignedVertex::new(
            vid(1),
            RoundNumber::ZERO,
            vec![], // No parents.
            vec![],
            vec![],
            PartialProofWitness::empty(),
        );
        assert!(v.has_quorum(7));
        assert!(v.has_quorum(75));
    }

    // ---------- parents_are_distinct ----------

    #[test]
    fn parents_are_distinct_empty_is_distinct() {
        let v = UnsignedVertex::new(
            vid(1),
            RoundNumber::new(1),
            vec![],
            vec![],
            vec![],
            PartialProofWitness::empty(),
        );
        assert!(v.parents_are_distinct());
    }

    #[test]
    fn parents_are_distinct_all_unique() {
        let mut v = fixed_unsigned();
        v.parents = vec![vxid(1), vxid(2), vxid(3)];
        assert!(v.parents_are_distinct());
    }

    #[test]
    fn parents_are_distinct_detects_duplicate() {
        let mut v = fixed_unsigned();
        v.parents = vec![vxid(1), vxid(2), vxid(1)];
        assert!(!v.parents_are_distinct());
    }

    // ---------- BCS round-trips ----------

    #[test]
    fn unsigned_vertex_bcs_round_trip() {
        let v = fixed_unsigned();
        let bytes = bcs::to_bytes(&v).unwrap();
        let decoded: UnsignedVertex = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn vertex_bcs_round_trip() {
        let v = Vertex::new(fixed_unsigned(), VertexSignature::from_bytes([0xAB; 48]));
        let bytes = bcs::to_bytes(&v).unwrap();
        let decoded: Vertex = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(v, decoded);
    }

    #[test]
    fn vertex_signature_bcs_round_trip() {
        let s = VertexSignature::from_bytes([0xCD; 48]);
        let bytes = bcs::to_bytes(&s).unwrap();
        let decoded: VertexSignature = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
        assert_eq!(bytes.len(), 48);
    }

    #[test]
    fn transaction_envelope_bcs_round_trip() {
        let tx = TransactionEnvelope::new(vec![1, 2, 3, 4, 5]);
        let bytes = bcs::to_bytes(&tx).unwrap();
        let decoded: TransactionEnvelope = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(tx, decoded);
    }

    #[test]
    fn decryption_share_bcs_round_trip() {
        let s = DecryptionShare::new(vec![0xFF; 32]);
        let bytes = bcs::to_bytes(&s).unwrap();
        let decoded: DecryptionShare = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(s, decoded);
    }

    #[test]
    fn proof_witness_bcs_round_trip() {
        let w = PartialProofWitness::new(vec![0x42; 64]);
        let bytes = bcs::to_bytes(&w).unwrap();
        let decoded: PartialProofWitness = bcs::from_bytes(&bytes).unwrap();
        assert_eq!(w, decoded);
    }

    // ---------- VertexBuilder ----------

    #[test]
    fn builder_constructs_unsigned_vertex() {
        let v = VertexBuilder::new(vid(1), RoundNumber::new(5))
            .add_parent(vxid(0xA1))
            .add_parent(vxid(0xA2))
            .add_transaction(TransactionEnvelope::new(vec![1, 2, 3]))
            .build_unsigned();
        assert_eq!(v.author, vid(1));
        assert_eq!(v.round, RoundNumber::new(5));
        assert_eq!(v.parents.len(), 2);
        assert_eq!(v.transactions.len(), 1);
    }

    #[test]
    fn builder_with_parents_overwrites() {
        let v = VertexBuilder::new(vid(1), RoundNumber::new(1))
            .add_parent(vxid(0xAA))
            .with_parents(vec![vxid(0xBB), vxid(0xCC)])
            .build_unsigned();
        assert_eq!(v.parents, vec![vxid(0xBB), vxid(0xCC)]);
    }

    #[test]
    fn builder_build_with_signature() {
        let signature = VertexSignature::from_bytes([0xFE; 48]);
        let v = VertexBuilder::new(vid(1), RoundNumber::new(1))
            .add_parent(vxid(0xAA))
            .with_signature(signature)
            .build();
        assert_eq!(v.signature, signature);
        assert_eq!(v.author(), vid(1));
        assert_eq!(v.round(), RoundNumber::new(1));
        assert_eq!(v.parents(), &[vxid(0xAA)]);
    }

    #[test]
    #[should_panic(expected = "with_signature() to have been called")]
    fn builder_build_panics_without_signature() {
        let _ = VertexBuilder::new(vid(1), RoundNumber::new(1)).build();
    }

    /// `Vertex::id()` matches the underlying body's derive_id —
    /// pinned for forward-compat with Phase 7.7 verification
    /// logic.
    #[test]
    fn vertex_id_matches_body_derive_id() {
        let signature = VertexSignature::placeholder();
        let v = Vertex::new(fixed_unsigned(), signature);
        assert_eq!(v.id(), v.body.derive_id());
    }

    // ---------- equivocation-relevant invariants ----------

    /// §8.1.5 equivocation = two distinct signed vertices for
    /// the same `(author, round)`. Two such bodies necessarily
    /// produce two different `VertexId`s (because at least one
    /// other field — parents / transactions / shares / witness —
    /// must differ). Pin: same `(author, round)` but distinct
    /// parents yields distinct ids.
    #[test]
    fn equivocation_bodies_have_distinct_ids() {
        let body_1 = UnsignedVertex::new(
            vid(1),
            RoundNumber::new(5),
            vec![vxid(0xAA)],
            vec![],
            vec![],
            PartialProofWitness::empty(),
        );
        let body_2 = UnsignedVertex::new(
            vid(1),              // same author
            RoundNumber::new(5), // same round
            vec![vxid(0xBB)],    // different parents
            vec![],
            vec![],
            PartialProofWitness::empty(),
        );
        assert_ne!(body_1.derive_id(), body_2.derive_id());
    }

    /// Identical bodies produce identical ids — the
    /// content-addressing invariant.
    #[test]
    fn identical_bodies_have_identical_ids() {
        let body_1 = fixed_unsigned();
        let body_2 = fixed_unsigned();
        assert_eq!(body_1.derive_id(), body_2.derive_id());
    }
}
