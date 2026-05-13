//! Mempool decryption per whitepaper §3.6 + §3.8 + §8.4.
//!
//! Phase 7.7d deliverable — the decryption-flow layer that
//! converts committed-wave output (per-wave `Vec<VertexId>` from
//! the Phase 7.7c [`CommitSequencer`]) into the cleartext-
//! transaction sequence the §6 execution layer consumes.
//!
//! [`CommitSequencer`]: crate::commit_sequencer::CommitSequencer
//!
//! # Spec basis
//!
//! Per §8.3.3 step 4 ("Transaction extraction"): "The protocol
//! extracts all transactions from the committed vertices,
//! applies them in causal order, and updates chain state."
//! The "extracts" step branches on regime per §8.4:
//!
//! - **Threshold regime** (N ≥ 15, §8.4.3): vertices carry
//!   threshold-encrypted envelopes. Validators publish
//!   decryption shares; once 2/3+1 valid shares are collected
//!   for a ciphertext-identity, the cleartext recovers via the
//!   §3.6 combine+decapsulate flow.
//!
//! - **Time-lock regime** (N < 15, §8.4.4): vertices carry
//!   time-lock VDF envelopes. The round anchor's vertex
//!   publishes the anchor's decryption atomically with the
//!   ciphertext (§8.4.4 Mitigation B); observers verify the
//!   anchor's evaluation proof and recover the cleartext via
//!   the §3.8.8 [`vdf::envelope::verify_decryption`] fast path.
//!
//! [`vdf::envelope::verify_decryption`]: adamant_crypto::vdf::envelope::verify_decryption
//!
//! # Phase 7.7d scope
//!
//! Phase 7.7d ships the **decryption primitives and the stateful
//! threshold-share accumulator** — the type-level + state-machine
//! foundation that Phase 7.7e end-to-end integration tests
//! consume. Specifically:
//!
//! - [`extract_envelopes`] — walks a committed wave's `ordered`
//!   list and BCS-decodes each vertex's `transactions` field
//!   into [`MempoolEnvelope`]s.
//! - [`decrypt_time_lock`] — pure-function verification of the
//!   round anchor's time-lock decryption against an envelope.
//!   Wraps [`vdf::envelope::verify_decryption`] and packages the
//!   result as a [`DecryptedTransaction`].
//! - [`ValidatorDecryptionShare`] — the BCS-shape inside a
//!   vertex's [`crate::DecryptionShare`] (`.bytes`). Binds an
//!   identity to a §3.6 threshold-decryption share.
//! - [`ThresholdShareAccumulator`] — the stateful collector that
//!   tracks per-identity ciphertexts + collected shares; emits
//!   a [`DecryptedTransaction`] once the §3.6 threshold is met.
//!
//! What Phase 7.7d does NOT ship (deferred to later sub-arcs):
//!
//! - DKG (§8.4.3): the distributed key generation that produces
//!   the threshold public-key shares. Phase 7.7d's accumulator
//!   accepts the `PublicKeyShare` registry at construction;
//!   sourcing it is a follow-on sub-arc.
//! - Active-set ↔ validator-share binding via on-chain
//!   `Validator` records. Phase 7.7d treats the registry as a
//!   `BTreeMap<u32, PublicKeyShare>` input.
//! - Anchor-decryption wire binding: where in a vertex the
//!   round anchor publishes its time-lock `TimeLockDecryption`.
//!   Phase 7.7d's [`decrypt_time_lock`] is a pure function
//!   taking `(envelope, decryption)` as separate inputs; the
//!   wire-binding for pairing them inside a vertex lands at
//!   Phase 7.7e integration or a Phase 7.6 wire amendment.
//!
//! # Phase 7.7 sub-arc roadmap (updated)
//!
//! | Sub-arc | Surface | Status |
//! |---------|---------|--------|
//! | 7.7a   | DAG storage + insertion validation | closed |
//! | 7.7b   | Direct commit-wave logic | closed |
//! | 7.7c   | Indirect commit + halt detection | closed |
//! | 7.7d   | Mempool decryption (this sub-arc) | **THIS SUB-ARC** |
//! | 7.7e   | End-to-end integration tests | pending |

use std::collections::{BTreeMap, HashMap};

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use adamant_crypto::symmetric::{Key as SymmetricKey, Nonce as SymmetricNonce, NONCE_BYTES};
use adamant_crypto::threshold::{
    self, CiphertextHeader as ThresholdHeader, DecryptionShare as ThresholdShare, PublicKeyShare,
    DECRYPTION_SHARE_BYTES,
};
use adamant_crypto::vdf::envelope::{self, EnvelopeError};
use adamant_crypto::vdf::{TimeLockDecryption, TimeLockEnvelope, TimeLockParameters};

use crate::dag::DagState;
use crate::mempool::{MempoolEnvelope, ThresholdMempoolEnvelope};
use crate::vertex::{DecryptionShare as VertexDecryptionShare, VertexId};

/// Typed errors produced by the Phase 7.7d decryption surface.
///
/// Non-`#[non_exhaustive]` per consensus-critical-surface
/// discipline (same posture as [`crate::DagError`],
/// [`crate::CommitDecision`], [`crate::SequencerError`]).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MempoolDecryptionError {
    /// A vertex id referenced by the committed wave is not
    /// present in the supplied DAG state. Indicates caller-side
    /// inconsistency between the [`crate::CommitSequencer`]
    /// outputs and the DAG snapshot.
    VertexNotInDag(VertexId),

    /// A vertex's `transactions[index]` failed to BCS-decode as
    /// a [`MempoolEnvelope`]. Either malformed wire data or a
    /// regime/version mismatch.
    EnvelopeDecodeFailed {
        /// The vertex carrying the malformed envelope.
        vertex: VertexId,
        /// The position within the vertex's transaction list.
        index: usize,
    },

    /// The anchor's time-lock decryption fails to verify against
    /// the envelope under the chain-fixed parameters. Either
    /// the anchor's evaluation proof is invalid or the AEAD
    /// authentication tag check fails. Per §8.4.4 the round
    /// anchor's vertex is consensus-bound (equivocation
    /// slashable at 100% per §8.1.5), so this error indicates
    /// either a malformed user envelope or a buggy anchor.
    TimeLockDecryptionFailed {
        /// The vertex whose decryption failed.
        vertex: VertexId,
        /// The position within the vertex's transaction list.
        index: usize,
    },

    /// A [`ValidatorDecryptionShare`] failed to BCS-decode from
    /// a vertex's `threshold_shares[i].bytes`.
    ShareDecodeFailed {
        /// The vertex carrying the malformed share.
        vertex: VertexId,
        /// The position within the vertex's share list.
        index: usize,
    },

    /// The §3.6 threshold-share pairing check failed for a
    /// submitted share. Either the validator's signing key was
    /// not the expected one (impersonation) or the share is
    /// malformed in a way the raw-bytes decode didn't catch.
    /// Discarded before reaching `combine` per the §3.6.1
    /// consensus-critical share-validation discipline.
    ShareVerificationFailed {
        /// The ciphertext identity the share was submitted for.
        identity: Vec<u8>,
        /// The validator-index (1-indexed) of the share.
        share_index: u32,
    },

    /// A share was submitted with a `share_index` that does not
    /// appear in the [`ThresholdShareAccumulator`]'s validator
    /// public-key registry. The caller's chain-state lookup is
    /// inconsistent with the accumulator's snapshot.
    UnknownValidatorShareIndex {
        /// The identity for which the unknown-index share was
        /// submitted.
        identity: Vec<u8>,
        /// The unknown share index.
        share_index: u32,
    },

    /// The §3.6 Lagrange-interpolation [`combine`](threshold::combine)
    /// step failed. Indicates pre-combine share validation
    /// missed a malformed share — should not occur in practice
    /// since [`ThresholdShareAccumulator::submit_share`] validates
    /// every share before storing.
    CombineFailed {
        /// The identity whose share-set failed to combine.
        identity: Vec<u8>,
    },

    /// The §3.6 [`decapsulate`](threshold::decapsulate) step
    /// failed. The combined share or ciphertext header does not
    /// produce a valid symmetric key.
    DecapsulationFailed {
        /// The identity whose combined share failed to
        /// decapsulate.
        identity: Vec<u8>,
    },

    /// The ChaCha20-Poly1305 AEAD authentication tag check
    /// failed during ciphertext decryption. The derived
    /// symmetric key does not match the encryption-time key —
    /// either the threshold combine produced a wrong key (e.g.,
    /// pre-combine validation was inconsistent) or the
    /// ciphertext was tampered with.
    AeadDecryptionFailed {
        /// The identity whose ciphertext failed AEAD.
        identity: Vec<u8>,
    },

    /// The ciphertext is shorter than the 12-byte nonce prefix
    /// the §3.5 AEAD layout requires.
    CiphertextTooShort {
        /// The identity whose ciphertext was truncated.
        identity: Vec<u8>,
    },
}

impl core::fmt::Display for MempoolDecryptionError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::VertexNotInDag(id) => write!(f, "vertex {id:?} not in DAG"),
            Self::EnvelopeDecodeFailed { vertex, index } => {
                write!(f, "envelope decode failed: vertex={vertex:?} index={index}")
            }
            Self::TimeLockDecryptionFailed { vertex, index } => write!(
                f,
                "time-lock decryption failed: vertex={vertex:?} index={index}"
            ),
            Self::ShareDecodeFailed { vertex, index } => {
                write!(f, "share decode failed: vertex={vertex:?} index={index}")
            }
            Self::ShareVerificationFailed {
                identity,
                share_index,
            } => write!(
                f,
                "share verification failed: identity={} share_index={share_index}",
                hex_short(identity)
            ),
            Self::UnknownValidatorShareIndex {
                identity,
                share_index,
            } => write!(
                f,
                "unknown validator share_index={share_index} for identity={}",
                hex_short(identity)
            ),
            Self::CombineFailed { identity } => {
                write!(
                    f,
                    "share combine failed for identity={}",
                    hex_short(identity)
                )
            }
            Self::DecapsulationFailed { identity } => write!(
                f,
                "decapsulation failed for identity={}",
                hex_short(identity)
            ),
            Self::AeadDecryptionFailed { identity } => write!(
                f,
                "AEAD decryption failed for identity={}",
                hex_short(identity)
            ),
            Self::CiphertextTooShort { identity } => write!(
                f,
                "ciphertext too short for identity={}",
                hex_short(identity)
            ),
        }
    }
}

impl std::error::Error for MempoolDecryptionError {}

/// Short hex prefix for diagnostic display of opaque-bytes
/// identities. Six hex chars (3 bytes) is enough for at-a-glance
/// disambiguation in logs without burning console width.
fn hex_short(bytes: &[u8]) -> String {
    use core::fmt::Write as _;
    let take = core::cmp::min(bytes.len(), 3);
    let mut s = String::with_capacity(take * 2);
    for b in &bytes[..take] {
        let _ = write!(s, "{b:02x}");
    }
    if bytes.len() > take {
        s.push('…');
    }
    s
}

/// A successfully-decrypted mempool transaction ready for the §6
/// execution layer to consume.
///
/// `plaintext` is the BCS-encoded transaction payload (cleared
/// per §3.5 ChaCha20-Poly1305 + the §3.6 / §3.8 KEM wrap). The
/// execution layer further BCS-decodes this into the AVM
/// `Transaction` type at Phase 7.7e integration.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecryptedTransaction {
    /// The committed vertex this transaction originated from.
    pub origin_vertex: VertexId,
    /// Position within `origin_vertex.transactions`. Together
    /// with `origin_vertex` uniquely identifies the source.
    ///
    /// Encoded as `u32` for cross-platform wire portability —
    /// BCS encodes `usize` differently on 32-bit vs 64-bit
    /// targets. Per-vertex transaction counts are bounded by
    /// the §9.5.x mempool admission caps; `u32` is more than
    /// sufficient. Pre-Phase-10 audit closure.
    pub origin_index: u32,
    /// Cleartext transaction bytes (BCS-encoded AVM
    /// `Transaction` at Phase 7.7e).
    pub plaintext: Vec<u8>,
}

/// BCS-shape inside a vertex's [`crate::DecryptionShare`]
/// (`.bytes`). Binds an identity to a §3.6 threshold-decryption
/// share.
///
/// The Phase 7.3 vertex wire structure carries `threshold_shares:
/// Vec<DecryptionShare>` as opaque bytes; Phase 7.7d pins the
/// inner shape here. Each share is BCS-encoded
/// `ValidatorDecryptionShare`; reading a vertex's shares means
/// BCS-decoding each `.bytes` into this type.
///
/// # Wire layout
///
/// BCS encoding of:
/// - `identity: Vec<u8>` (length-prefixed)
/// - `share_index: u32` (little-endian; matches
///   `threshold::DecryptionShare.index()` 1-indexed validator)
/// - `share_bytes: [u8; 48]` (the
///   [`DECRYPTION_SHARE_BYTES`](threshold::DECRYPTION_SHARE_BYTES)
///   compressed G₁ point that is the share)
///
/// The encoding is consensus-binding: changing field order
/// or types is a hard fork.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ValidatorDecryptionShare {
    /// The ciphertext identity this share is for.
    pub identity: Vec<u8>,
    /// 1-indexed validator share number.
    pub share_index: u32,
    /// The 48-byte compressed G₁ point that is the share.
    #[serde(with = "BigArray")]
    pub share_bytes: [u8; DECRYPTION_SHARE_BYTES],
}

impl ValidatorDecryptionShare {
    /// Construct from raw fields.
    #[must_use]
    pub const fn new(
        identity: Vec<u8>,
        share_index: u32,
        share_bytes: [u8; DECRYPTION_SHARE_BYTES],
    ) -> Self {
        Self {
            identity,
            share_index,
            share_bytes,
        }
    }

    /// BCS-encode this share for storage inside a vertex's
    /// [`crate::DecryptionShare`] (`.bytes`).
    ///
    /// # Errors
    ///
    /// Returns [`bcs::Error`] only if BCS serialisation fails,
    /// which cannot occur for this struct's plain-data shape
    /// (no custom serialisers).
    pub fn to_bytes(&self) -> Result<Vec<u8>, bcs::Error> {
        bcs::to_bytes(self)
    }

    /// BCS-decode from raw bytes (typically a vertex's
    /// [`crate::DecryptionShare`] (`.bytes`)).
    ///
    /// # Errors
    ///
    /// Returns [`bcs::Error`] on malformed BCS.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, bcs::Error> {
        bcs::from_bytes(bytes)
    }
}

// ---------------------------------------------------------------
// Committed-wave envelope extraction
// ---------------------------------------------------------------

/// Walk a committed wave's `ordered` vertex list and BCS-decode
/// each vertex's `transactions` field into [`MempoolEnvelope`]s.
///
/// Returns the `(origin_vertex, origin_index, envelope)`
/// triples in committed-wave order — first the earliest
/// vertex's transactions in order, then the next vertex's, and
/// so on. This is the ordering the §6 execution layer consumes
/// at step 4 of §8.3.3.
///
/// # Errors
///
/// - [`MempoolDecryptionError::VertexNotInDag`] if any id in
///   `ordered` is missing from the DAG.
/// - [`MempoolDecryptionError::EnvelopeDecodeFailed`] if a
///   vertex's `transactions[i]` does not BCS-decode as a
///   [`MempoolEnvelope`].
pub fn extract_envelopes(
    dag: &DagState,
    ordered: &[VertexId],
) -> Result<Vec<(VertexId, usize, MempoolEnvelope)>, MempoolDecryptionError> {
    let mut out = Vec::new();
    for vid in ordered {
        let vertex = dag
            .vertex(vid)
            .ok_or(MempoolDecryptionError::VertexNotInDag(*vid))?;
        for (idx, env_wrapper) in vertex.body().transactions.iter().enumerate() {
            let envelope: MempoolEnvelope =
                bcs::from_bytes(env_wrapper.as_bytes()).map_err(|_| {
                    MempoolDecryptionError::EnvelopeDecodeFailed {
                        vertex: *vid,
                        index: idx,
                    }
                })?;
            out.push((*vid, idx, envelope));
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------
// Time-lock decryption (§8.4.4)
// ---------------------------------------------------------------

/// Verify the round anchor's time-lock decryption against an
/// envelope per §3.8.8 + §8.4.4.
///
/// This is the **observer-side fast path**: takes the round
/// anchor's published `decryption` and the original envelope,
/// runs [`vdf::envelope::verify_decryption`] (~128 class-group
/// operations + a ChaCha20-Poly1305 decryption; sub-millisecond
/// vs the anchor's ~10-15 seconds of VDF work per §3.8.2), and
/// packages the recovered plaintext as a [`DecryptedTransaction`].
///
/// Per §8.4.4 Mitigation B the anchor's decryption is published
/// atomically with the ciphertext in the anchor's vertex.
/// Equivocation (publishing two different vertices for the same
/// round) is slashable per §8.1.5 at 100% of the validator's
/// stake — so a verification failure here surfaces either a
/// malformed user envelope or an honest implementation bug, not
/// adversarial behaviour.
///
/// # Errors
///
/// - [`MempoolDecryptionError::TimeLockDecryptionFailed`] —
///   any [`EnvelopeError`] from §3.8.8 verify_decryption. The
///   inner cause is folded into the single variant for
///   consensus-stable surface size; the variant carries source
///   vertex + index for traceability.
///
/// # Panics
///
/// Cannot panic in practice. The internal `expect` on
/// `u32::try_from(origin_index)` is a contract assertion:
/// per-vertex transaction counts are bounded below `u32::MAX`
/// by the §9.5 mempool admission caps. A panic here would
/// indicate a defect in the vertex-admission layer, not a
/// runtime failure mode.
///
/// [`vdf::envelope::verify_decryption`]: adamant_crypto::vdf::envelope::verify_decryption
pub fn decrypt_time_lock(
    params: &TimeLockParameters,
    origin_vertex: VertexId,
    origin_index: usize,
    envelope: &TimeLockEnvelope,
    decryption: &TimeLockDecryption,
) -> Result<DecryptedTransaction, MempoolDecryptionError> {
    let plaintext = envelope::verify_decryption(params, envelope, decryption).map_err(
        |_e: EnvelopeError| MempoolDecryptionError::TimeLockDecryptionFailed {
            vertex: origin_vertex,
            index: origin_index,
        },
    )?;
    // Convert internal usize to consensus-stable u32 at the
    // wire-binding boundary. Per-vertex transaction counts are
    // bounded by mempool admission limits; truncation is
    // structurally impossible.
    let origin_index_u32: u32 = u32::try_from(origin_index).expect(
        "Adamant invariant: per-vertex transaction count is bounded below u32::MAX by §9.5 mempool admission caps",
    );
    Ok(DecryptedTransaction {
        origin_vertex,
        origin_index: origin_index_u32,
        plaintext,
    })
}

// ---------------------------------------------------------------
// Threshold-share accumulator (§8.4.3 + §3.6)
// ---------------------------------------------------------------

/// State per pending threshold-encrypted identity inside the
/// accumulator. Tracks the ciphertext that arrived alongside
/// the identity plus the running share collection.
#[derive(Clone, Debug)]
struct PendingThreshold {
    origin_vertex: VertexId,
    origin_index: usize,
    /// `None` if shares arrived before the envelope. Set on
    /// the first `submit_envelope` call for this identity.
    header: Option<ThresholdHeader>,
    ciphertext_body: Vec<u8>,
    shares: BTreeMap<u32, ThresholdShare>,
}

/// Stateful threshold-decryption-share accumulator per §3.6 +
/// §8.4.3.
///
/// Tracks two parallel maps keyed by ciphertext identity:
/// 1. The ciphertext envelope (header + body) that the identity
///    was advertised against.
/// 2. The running set of validator decryption shares for that
///    identity.
///
/// On every [`Self::submit_share`] call, the accumulator
/// **eagerly validates** the share against the corresponding
/// validator public-key share — discarding malformed shares
/// before they reach [`combine`](threshold::combine) per the
/// §3.6.1 consensus-critical share-validation discipline.
///
/// Once [`Self::try_decrypt`] is called for an identity with
/// `>= threshold` valid shares + a registered envelope, it runs
/// the §3.6 combine + decapsulate + AEAD-decrypt cycle and
/// returns the recovered [`DecryptedTransaction`].
///
/// # Memory shape
///
/// Bounded by the number of in-flight ciphertexts × `threshold`
/// shares each. The accumulator does NOT garbage-collect on its
/// own — caller (Phase 7.7e integration) is responsible for
/// invoking [`Self::take`] on resolved identities to free
/// memory.
#[derive(Clone, Debug)]
pub struct ThresholdShareAccumulator {
    pk_shares: BTreeMap<u32, PublicKeyShare>,
    threshold: usize,
    pending: HashMap<Vec<u8>, PendingThreshold>,
}

impl ThresholdShareAccumulator {
    /// New accumulator with the supplied validator public-key
    /// share registry and §3.6 reconstruction threshold.
    ///
    /// `pk_shares` maps 1-indexed validator number to that
    /// validator's [`PublicKeyShare`]. Phase 7.7d's accumulator
    /// is opinion-free about how the registry is populated — at
    /// Phase 7.7e integration, the caller derives it from chain
    /// state (the on-chain validator records produced by §8's
    /// DKG).
    ///
    /// `threshold` is the §3.6 reconstruction threshold `t` —
    /// the minimum number of valid shares required to recover
    /// the symmetric key. For Adamant's 2/3+1 quorum at active-
    /// set size `N`, this is `quorum_threshold(N)` from Phase
    /// 7.2's schedule module.
    #[must_use]
    pub fn new(pk_shares: BTreeMap<u32, PublicKeyShare>, threshold: usize) -> Self {
        Self {
            pk_shares,
            threshold,
            pending: HashMap::new(),
        }
    }

    /// The §3.6 reconstruction threshold this accumulator was
    /// constructed with.
    #[must_use]
    pub const fn threshold(&self) -> usize {
        self.threshold
    }

    /// Number of distinct ciphertext identities the accumulator
    /// currently holds pending.
    #[must_use]
    pub fn pending_count(&self) -> usize {
        self.pending.len()
    }

    /// Number of shares collected for a specific identity.
    /// Returns 0 if the identity is unknown to the accumulator
    /// (no envelope submitted yet).
    #[must_use]
    pub fn share_count(&self, identity: &[u8]) -> usize {
        self.pending.get(identity).map_or(0, |p| p.shares.len())
    }

    /// Register a threshold-encrypted envelope. Stores the
    /// ciphertext alongside any existing shares for the same
    /// identity (shares may arrive before the envelope they
    /// belong to does — e.g., share publication lags or the
    /// vertices are processed out of order).
    ///
    /// Idempotent: re-submitting the same envelope is a no-op
    /// (the stored header + body are not overwritten with
    /// identical values). Different ciphertexts under the same
    /// identity are NOT defended against here — that's a
    /// caller-side invariant (the §3.6 identity uniquely
    /// determines the ciphertext under the encryption scheme).
    ///
    /// # Errors
    ///
    /// Returns [`MempoolDecryptionError::EnvelopeDecodeFailed`]
    /// if the 96-byte `ciphertext_header` is not a valid §3.6
    /// [`CiphertextHeader`](threshold::CiphertextHeader) (does
    /// not decode as a G₂ compressed point).
    pub fn submit_envelope(
        &mut self,
        origin_vertex: VertexId,
        origin_index: usize,
        envelope: ThresholdMempoolEnvelope,
    ) -> Result<(), MempoolDecryptionError> {
        let header = ThresholdHeader::from_bytes(&envelope.ciphertext_header).map_err(|_| {
            MempoolDecryptionError::EnvelopeDecodeFailed {
                vertex: origin_vertex,
                index: origin_index,
            }
        })?;
        let entry = self
            .pending
            .entry(envelope.identity.clone())
            .or_insert_with(|| PendingThreshold {
                origin_vertex,
                origin_index,
                header: None,
                ciphertext_body: Vec::new(),
                shares: BTreeMap::new(),
            });
        // Bind the envelope to the pending record on first
        // submission. If an envelope-less share-only entry
        // already exists (shares arrived first), this
        // populates the header + ciphertext_body without
        // disturbing the collected shares. The originating
        // vertex/index pin to the envelope's source.
        if entry.header.is_none() {
            entry.header = Some(header);
            entry.ciphertext_body = envelope.ciphertext;
            entry.origin_vertex = origin_vertex;
            entry.origin_index = origin_index;
        }
        Ok(())
    }

    /// Submit a validator's decryption share for an identity.
    /// Validates the share against the registered
    /// [`PublicKeyShare`] before storing.
    ///
    /// If no envelope has been submitted for this identity yet,
    /// the share is stored in an envelope-less pending slot;
    /// [`Self::try_decrypt`] will return `None` until the
    /// envelope arrives.
    ///
    /// # Errors
    ///
    /// - [`MempoolDecryptionError::ShareDecodeFailed`] if the
    ///   vertex share's `.bytes` does not BCS-decode as a
    ///   [`ValidatorDecryptionShare`].
    /// - [`MempoolDecryptionError::UnknownValidatorShareIndex`]
    ///   if `share_index` is not in the public-key registry.
    /// - [`MempoolDecryptionError::ShareVerificationFailed`] if
    ///   the §3.6 pairing-check verify fails.
    pub fn submit_share(
        &mut self,
        origin_vertex: VertexId,
        origin_index: usize,
        share_wrapper: &VertexDecryptionShare,
    ) -> Result<(), MempoolDecryptionError> {
        let decoded =
            ValidatorDecryptionShare::from_bytes(share_wrapper.as_bytes()).map_err(|_| {
                MempoolDecryptionError::ShareDecodeFailed {
                    vertex: origin_vertex,
                    index: origin_index,
                }
            })?;
        let pk_share = self.pk_shares.get(&decoded.share_index).ok_or(
            MempoolDecryptionError::UnknownValidatorShareIndex {
                identity: decoded.identity.clone(),
                share_index: decoded.share_index,
            },
        )?;
        let threshold_share = ThresholdShare::from_bytes(decoded.share_index, &decoded.share_bytes)
            .map_err(|_| MempoolDecryptionError::ShareVerificationFailed {
                identity: decoded.identity.clone(),
                share_index: decoded.share_index,
            })?;
        threshold::verify_decryption_share(pk_share, &decoded.identity, &threshold_share).map_err(
            |_| MempoolDecryptionError::ShareVerificationFailed {
                identity: decoded.identity.clone(),
                share_index: decoded.share_index,
            },
        )?;
        // Find or initialise the pending entry. An envelope-less
        // pending slot uses placeholder origin vertex/index; the
        // first envelope to land cements those values via
        // submit_envelope above.
        let entry = self
            .pending
            .entry(decoded.identity.clone())
            .or_insert_with(|| PendingThreshold {
                origin_vertex,
                origin_index,
                header: None,
                ciphertext_body: Vec::new(),
                shares: BTreeMap::new(),
            });
        // Insert idempotently — same (index, identity) collisions
        // overwrite the existing share. The §3.6 verification has
        // already succeeded so the share is canonical.
        entry.shares.insert(decoded.share_index, threshold_share);
        Ok(())
    }

    /// Attempt to decrypt the ciphertext for `identity`.
    /// Returns:
    /// - `Ok(Some(transaction))` if the threshold is met AND
    ///   an envelope has been submitted AND combine + decapsulate
    ///   + AEAD all succeed.
    /// - `Ok(None)` if the threshold is not yet met OR no
    ///   envelope has been submitted yet for `identity`.
    /// - `Err(...)` if the cryptographic operations fail on
    ///   an already-validated share set (should not occur
    ///   under honest operation).
    ///
    /// Side effect on success: the pending entry for `identity`
    /// is removed (transition to "decrypted; consume once"). On
    /// failure, the pending entry remains in place.
    ///
    /// # Errors
    ///
    /// - [`MempoolDecryptionError::CombineFailed`]
    /// - [`MempoolDecryptionError::DecapsulationFailed`]
    /// - [`MempoolDecryptionError::CiphertextTooShort`]
    /// - [`MempoolDecryptionError::AeadDecryptionFailed`]
    ///
    /// # Panics
    ///
    /// Cannot panic in practice. The internal `expect("…")` on
    /// the public-key-share lookup is guarded by
    /// [`Self::submit_share`]'s pre-validation: every share
    /// stored in `pending.shares` has a corresponding entry in
    /// `pk_shares`. A panic here would indicate a caller
    /// mutation of `pk_shares` between submission and decryption
    /// (which the accumulator's API does not expose).
    pub fn try_decrypt(
        &mut self,
        identity: &[u8],
    ) -> Result<Option<DecryptedTransaction>, MempoolDecryptionError> {
        let Some(pending) = self.pending.get(identity) else {
            return Ok(None);
        };
        if pending.shares.len() < self.threshold {
            return Ok(None);
        }
        let Some(header) = pending.header.as_ref() else {
            // Shares arrived but no envelope yet.
            return Ok(None);
        };
        if pending.ciphertext_body.is_empty() {
            return Ok(None);
        }

        // Build the (share, pk_share) pairs for `combine`.
        let pairs: Vec<(&ThresholdShare, &PublicKeyShare)> = pending
            .shares
            .iter()
            .take(self.threshold)
            .map(|(idx, share)| {
                let pk = self.pk_shares.get(idx).expect(
                    "share_count >= threshold pre-validated against pk_shares registry at submit_share time",
                );
                (share, pk)
            })
            .collect();
        let combined = threshold::combine(identity, &pairs).map_err(|_| {
            MempoolDecryptionError::CombineFailed {
                identity: identity.to_vec(),
            }
        })?;
        let key: SymmetricKey =
            threshold::decapsulate(&combined, header, identity).map_err(|_| {
                MempoolDecryptionError::DecapsulationFailed {
                    identity: identity.to_vec(),
                }
            })?;
        if pending.ciphertext_body.len() < NONCE_BYTES {
            return Err(MempoolDecryptionError::CiphertextTooShort {
                identity: identity.to_vec(),
            });
        }
        let nonce_slice: &[u8; NONCE_BYTES] = pending.ciphertext_body[..NONCE_BYTES]
            .try_into()
            .expect("length checked above");
        let nonce = SymmetricNonce(*nonce_slice);
        let body = &pending.ciphertext_body[NONCE_BYTES..];
        let plaintext: Vec<u8> = key.decrypt(&nonce, body, &[]).map_err(|_| {
            MempoolDecryptionError::AeadDecryptionFailed {
                identity: identity.to_vec(),
            }
        })?;

        let origin_vertex = pending.origin_vertex;
        // Convert internal usize to consensus-stable u32 at the
        // wire-binding boundary.
        let origin_index: u32 = u32::try_from(pending.origin_index).expect(
            "Adamant invariant: per-vertex transaction count is bounded below u32::MAX by §9.5 mempool admission caps",
        );
        // Consume the pending entry on success.
        self.pending.remove(identity);
        Ok(Some(DecryptedTransaction {
            origin_vertex,
            origin_index,
            plaintext,
        }))
    }

    /// Remove a pending entry without consuming it as a
    /// decryption. Useful for caller-side GC (e.g., when a
    /// ciphertext is known to be unrecoverable because its
    /// validators left the active set).
    pub fn forget(&mut self, identity: &[u8]) -> bool {
        self.pending.remove(identity).is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_crypto::threshold::{MasterPublicKey, TrustedDealerShares};
    use rand_core::OsRng;

    use crate::active_set::ActiveSet;
    use crate::epoch::{EpochNumber, RoundNumber};
    use crate::identity::{ValidatorId, ValidatorPublicKeys};
    use crate::mempool::ThresholdMempoolEnvelope;
    use crate::vertex::{
        DecryptionShare as VertexDecryptionShare, TransactionEnvelope, Vertex, VertexBuilder,
        VertexSignature, BLS_SIGNATURE_BYTES,
    };

    fn validator_pubkeys(seed: u8) -> ValidatorPublicKeys {
        ValidatorPublicKeys::new([seed; 32], [seed; 1952], [seed; 96], [seed; 48])
    }

    fn validator_id(seed: u8) -> ValidatorId {
        validator_pubkeys(seed).derive_id()
    }

    fn fixture_active_set(n: u8) -> ActiveSet {
        let mut set = ActiveSet::new();
        for seed in 1..=n {
            set.register(validator_id(seed), EpochNumber::default())
                .expect("register");
        }
        set
    }

    /// Build a genesis-round vertex with the supplied
    /// transaction-bytes payloads.
    fn make_vertex_with_txs(author_seed: u8, txs: Vec<Vec<u8>>) -> Vertex {
        let mut b = VertexBuilder::new(validator_id(author_seed), RoundNumber::default());
        for tx in txs {
            b = b.add_transaction(TransactionEnvelope::new(tx));
        }
        b.with_signature(VertexSignature::from_bytes([0u8; BLS_SIGNATURE_BYTES]))
            .build()
    }

    // ---- ValidatorDecryptionShare ----

    #[test]
    fn validator_decryption_share_bcs_round_trip() {
        let s = ValidatorDecryptionShare::new(b"identity-xyz".to_vec(), 7, [0xa5u8; 48]);
        let bytes = s.to_bytes().expect("encode");
        let decoded = ValidatorDecryptionShare::from_bytes(&bytes).expect("decode");
        assert_eq!(s, decoded);
    }

    #[test]
    fn validator_decryption_share_distinct_identities_distinct_bytes() {
        let a = ValidatorDecryptionShare::new(b"id-a".to_vec(), 1, [0u8; 48])
            .to_bytes()
            .expect("encode a");
        let b = ValidatorDecryptionShare::new(b"id-b".to_vec(), 1, [0u8; 48])
            .to_bytes()
            .expect("encode b");
        assert_ne!(a, b);
    }

    // ---- extract_envelopes ----

    #[test]
    fn extract_envelopes_returns_empty_for_empty_ordered() {
        let dag = DagState::new();
        let out = extract_envelopes(&dag, &[]).expect("ok");
        assert!(out.is_empty());
    }

    #[test]
    fn extract_envelopes_rejects_unknown_vertex() {
        let dag = DagState::new();
        let phantom = VertexId::from_bytes([0xFFu8; 32]);
        let err = extract_envelopes(&dag, &[phantom]).expect_err("must reject");
        match err {
            MempoolDecryptionError::VertexNotInDag(id) => assert_eq!(id, phantom),
            other => panic!("expected VertexNotInDag, got {other:?}"),
        }
    }

    #[test]
    fn extract_envelopes_decodes_threshold_envelopes() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let env1 = MempoolEnvelope::Threshold(ThresholdMempoolEnvelope {
            identity: b"id-1".to_vec(),
            ciphertext_header: [0xAAu8; 96],
            ciphertext: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13],
        });
        let env2 = MempoolEnvelope::Threshold(ThresholdMempoolEnvelope {
            identity: b"id-2".to_vec(),
            ciphertext_header: [0xBBu8; 96],
            ciphertext: vec![20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32],
        });
        let v = make_vertex_with_txs(
            1,
            vec![bcs::to_bytes(&env1).unwrap(), bcs::to_bytes(&env2).unwrap()],
        );
        let id = v.id();
        dag.insert(v, &active).expect("insert");
        let out = extract_envelopes(&dag, &[id]).expect("ok");
        assert_eq!(out.len(), 2);
        assert_eq!(out[0].0, id);
        assert_eq!(out[0].1, 0);
        assert_eq!(out[0].2, env1);
        assert_eq!(out[1].0, id);
        assert_eq!(out[1].1, 1);
        assert_eq!(out[1].2, env2);
    }

    #[test]
    fn extract_envelopes_rejects_malformed_envelope_bytes() {
        let active = fixture_active_set(7);
        let mut dag = DagState::new();
        let v = make_vertex_with_txs(1, vec![vec![0xFFu8; 4]]); // not valid BCS
        let id = v.id();
        dag.insert(v, &active).expect("insert");
        let err = extract_envelopes(&dag, &[id]).expect_err("must reject");
        assert!(matches!(
            err,
            MempoolDecryptionError::EnvelopeDecodeFailed { .. }
        ));
    }

    // ---- decrypt_time_lock ----

    #[test]
    fn decrypt_time_lock_round_trip_recovers_plaintext() {
        use adamant_crypto::vdf::setup::{derive_discriminant, hash_to_element};
        use num_bigint::BigInt;
        // Build small-T time-lock parameters for a fast test
        // (T=10 sequential squarings keeps it under a second).
        // 2048 is §3.8.2 minimum; T=10 keeps the test fast.
        let bit_len = 2048u32;
        let d: BigInt = derive_discriminant(&[0u8; 32], bit_len).expect("derive discriminant");
        let d_be = (-d.clone()).to_bytes_be().1;
        let params = TimeLockParameters {
            discriminant: d_be,
            time_parameter_t: 10,
        };
        // Sample a class-group generator.
        let g = hash_to_element(b"gen-seed", &d, 32).expect("hash to element");
        // Encrypt with deterministic nonce.
        let plaintext = b"hello time-lock world".to_vec();
        let mut g_seed = [0u8; 32];
        g_seed[0] = 1;
        let nonce_bytes = [9u8; 12];
        // We need the g_seed to be the hash_to_element input.
        // Use envelope::encrypt_with_randomness which takes
        // params + plaintext + g_seed + nonce_bytes.
        let _ = g;
        let (envelope, _h) =
            envelope::encrypt_with_randomness(&params, &plaintext, &g_seed, &nonce_bytes)
                .expect("encrypt");
        // Anchor decrypts (heavy).
        let (recovered_anchor, decryption) =
            envelope::decrypt(&params, &envelope).expect("anchor decrypt");
        assert_eq!(recovered_anchor, plaintext);
        // Phase 7.7d observer-side verify.
        let dummy_vertex = VertexId::from_bytes([0xC0u8; 32]);
        let tx = decrypt_time_lock(&params, dummy_vertex, 0, &envelope, &decryption)
            .expect("verify decryption");
        assert_eq!(tx.origin_vertex, dummy_vertex);
        assert_eq!(tx.origin_index, 0);
        assert_eq!(tx.plaintext, plaintext);
    }

    #[test]
    fn decrypt_time_lock_rejects_tampered_decryption() {
        use adamant_crypto::vdf::setup::derive_discriminant;
        use num_bigint::BigInt;
        // 2048 is §3.8.2 minimum; T=10 keeps the test fast.
        let bit_len = 2048u32;
        let d: BigInt = derive_discriminant(&[0u8; 32], bit_len).expect("derive");
        let d_be = (-d.clone()).to_bytes_be().1;
        let params = TimeLockParameters {
            discriminant: d_be,
            time_parameter_t: 10,
        };
        let plaintext = b"sensitive".to_vec();
        let mut g_seed = [0u8; 32];
        g_seed[0] = 2;
        let nonce_bytes = [3u8; 12];
        let (envelope, _h) =
            envelope::encrypt_with_randomness(&params, &plaintext, &g_seed, &nonce_bytes)
                .expect("encrypt");
        let (_pt, mut decryption) = envelope::decrypt(&params, &envelope).expect("decrypt");
        // Tamper: flip a byte in the solution.
        if let Some(b) = decryption.solution.encoded.get_mut(0) {
            *b ^= 0xFF;
        }
        let dummy_vertex = VertexId::from_bytes([0u8; 32]);
        let err = decrypt_time_lock(&params, dummy_vertex, 0, &envelope, &decryption)
            .expect_err("must reject");
        assert!(matches!(
            err,
            MempoolDecryptionError::TimeLockDecryptionFailed { .. }
        ));
    }

    // ---- ThresholdShareAccumulator ----

    fn fixture_threshold_setup(
        t: u32,
        n: u32,
    ) -> (
        MasterPublicKey,
        Vec<adamant_crypto::threshold::KeyShare>,
        BTreeMap<u32, PublicKeyShare>,
    ) {
        let shares =
            TrustedDealerShares::generate_for_testing_only(t, n, &mut OsRng).expect("dealer");
        let mpk = shares.master_public_key.clone();
        let pk_map: BTreeMap<u32, PublicKeyShare> = shares
            .public_key_shares
            .iter()
            .map(|p| (p.index(), p.clone()))
            .collect();
        (mpk, shares.key_shares, pk_map)
    }

    /// Encrypt a plaintext under the threshold scheme and produce
    /// the wire-shape (identity, header, ciphertext_body) plus a
    /// list of validator decryption shares (one per key_share).
    fn fixture_threshold_envelope(
        mpk: &MasterPublicKey,
        key_shares: &[adamant_crypto::threshold::KeyShare],
        identity: &[u8],
        plaintext: &[u8],
    ) -> (ThresholdMempoolEnvelope, Vec<ValidatorDecryptionShare>) {
        let (header, sym_key) =
            threshold::encapsulate(mpk, identity, &mut OsRng).expect("encapsulate");
        // Encrypt plaintext with AEAD using a random-but-fixed
        // nonce for determinism.
        let nonce = SymmetricNonce([7u8; NONCE_BYTES]);
        let body = sym_key
            .encrypt(&nonce, plaintext, &[])
            .expect("aead encrypt");
        let mut ciphertext = Vec::with_capacity(NONCE_BYTES + body.len());
        ciphertext.extend_from_slice(&nonce.0);
        ciphertext.extend_from_slice(&body);
        let envelope = ThresholdMempoolEnvelope {
            identity: identity.to_vec(),
            ciphertext_header: header.to_bytes(),
            ciphertext,
        };
        // Per-validator decryption shares.
        let mut shares = Vec::with_capacity(key_shares.len());
        for ks in key_shares {
            let ds = threshold::decryption_share(ks, identity);
            shares.push(ValidatorDecryptionShare::new(
                identity.to_vec(),
                ds.index(),
                ds.to_bytes(),
            ));
        }
        (envelope, shares)
    }

    #[test]
    fn accumulator_empty_at_construction() {
        let (_mpk, _ks, pk_map) = fixture_threshold_setup(3, 5);
        let acc = ThresholdShareAccumulator::new(pk_map, 3);
        assert_eq!(acc.pending_count(), 0);
        assert_eq!(acc.threshold(), 3);
        assert_eq!(acc.share_count(b"missing"), 0);
    }

    #[test]
    fn accumulator_full_round_trip_decrypts_at_threshold() {
        let (mpk, key_shares, pk_map) = fixture_threshold_setup(3, 5);
        let identity = b"id-rt".to_vec();
        let plaintext = b"hello threshold world".to_vec();
        let (envelope, shares) =
            fixture_threshold_envelope(&mpk, &key_shares, &identity, &plaintext);

        let mut acc = ThresholdShareAccumulator::new(pk_map, 3);
        let origin_vertex = VertexId::from_bytes([0x42u8; 32]);
        acc.submit_envelope(origin_vertex, 0, envelope)
            .expect("envelope");
        // Below threshold → None.
        for (i, share) in shares.iter().enumerate().take(2) {
            let wrapper = VertexDecryptionShare::new(share.to_bytes().expect("bcs"));
            acc.submit_share(origin_vertex, i, &wrapper).expect("share");
        }
        assert_eq!(acc.share_count(&identity), 2);
        assert!(acc.try_decrypt(&identity).expect("ok").is_none());
        // Third share → threshold met → decryption succeeds.
        let third = VertexDecryptionShare::new(shares[2].to_bytes().expect("bcs"));
        acc.submit_share(origin_vertex, 2, &third).expect("share 3");
        assert_eq!(acc.share_count(&identity), 3);
        let tx = acc.try_decrypt(&identity).expect("ok").expect("decrypted");
        assert_eq!(tx.plaintext, plaintext);
        assert_eq!(tx.origin_vertex, origin_vertex);
        assert_eq!(tx.origin_index, 0);
        // Pending entry consumed.
        assert_eq!(acc.pending_count(), 0);
        assert_eq!(acc.share_count(&identity), 0);
    }

    #[test]
    fn accumulator_returns_none_when_below_threshold() {
        let (mpk, key_shares, pk_map) = fixture_threshold_setup(3, 5);
        let identity = b"id-below".to_vec();
        let plaintext = b"never visible".to_vec();
        let (envelope, shares) =
            fixture_threshold_envelope(&mpk, &key_shares, &identity, &plaintext);
        let mut acc = ThresholdShareAccumulator::new(pk_map, 3);
        let origin_vertex = VertexId::from_bytes([0u8; 32]);
        acc.submit_envelope(origin_vertex, 0, envelope)
            .expect("envelope");
        let wrapper = VertexDecryptionShare::new(shares[0].to_bytes().expect("bcs"));
        acc.submit_share(origin_vertex, 0, &wrapper).expect("share");
        assert!(acc.try_decrypt(&identity).expect("ok").is_none());
        assert_eq!(acc.pending_count(), 1);
    }

    #[test]
    fn accumulator_returns_none_when_no_envelope_submitted_yet() {
        let (mpk, key_shares, pk_map) = fixture_threshold_setup(3, 5);
        let identity = b"id-shares-first".to_vec();
        let plaintext = b"pending envelope".to_vec();
        let (_envelope, shares) =
            fixture_threshold_envelope(&mpk, &key_shares, &identity, &plaintext);
        let mut acc = ThresholdShareAccumulator::new(pk_map, 3);
        let origin_vertex = VertexId::from_bytes([0u8; 32]);
        for (i, share) in shares.iter().enumerate().take(3) {
            let wrapper = VertexDecryptionShare::new(share.to_bytes().expect("bcs"));
            acc.submit_share(origin_vertex, i, &wrapper).expect("share");
        }
        // 3 shares but no envelope → None.
        assert_eq!(acc.share_count(&identity), 3);
        assert!(acc.try_decrypt(&identity).expect("ok").is_none());
    }

    #[test]
    fn accumulator_rejects_unknown_share_index() {
        let (_mpk, _ks, pk_map) = fixture_threshold_setup(3, 5);
        let mut acc = ThresholdShareAccumulator::new(pk_map, 3);
        // Construct a share with index that's not in the registry.
        let bogus =
            ValidatorDecryptionShare::new(b"id".to_vec(), 99, [0u8; DECRYPTION_SHARE_BYTES]);
        let wrapper = VertexDecryptionShare::new(bogus.to_bytes().expect("bcs"));
        let err = acc
            .submit_share(VertexId::from_bytes([0u8; 32]), 0, &wrapper)
            .expect_err("must reject");
        match err {
            MempoolDecryptionError::UnknownValidatorShareIndex { share_index, .. } => {
                assert_eq!(share_index, 99);
            }
            other => panic!("expected UnknownValidatorShareIndex, got {other:?}"),
        }
    }

    #[test]
    fn accumulator_rejects_tampered_share_bytes() {
        let (mpk, key_shares, pk_map) = fixture_threshold_setup(3, 5);
        let identity = b"id-tamper".to_vec();
        let plaintext = b"x".to_vec();
        let (_envelope, mut shares) =
            fixture_threshold_envelope(&mpk, &key_shares, &identity, &plaintext);
        // Tamper: zero out the first share's bytes.
        shares[0].share_bytes = [0u8; DECRYPTION_SHARE_BYTES];
        let wrapper = VertexDecryptionShare::new(shares[0].to_bytes().expect("bcs"));
        let mut acc = ThresholdShareAccumulator::new(pk_map, 3);
        let err = acc
            .submit_share(VertexId::from_bytes([0u8; 32]), 0, &wrapper)
            .expect_err("must reject");
        assert!(matches!(
            err,
            MempoolDecryptionError::ShareVerificationFailed { .. }
        ));
    }

    #[test]
    fn accumulator_rejects_malformed_share_bcs() {
        let (_mpk, _ks, pk_map) = fixture_threshold_setup(3, 5);
        let mut acc = ThresholdShareAccumulator::new(pk_map, 3);
        let wrapper = VertexDecryptionShare::new(vec![0xFFu8; 4]); // not valid BCS
        let err = acc
            .submit_share(VertexId::from_bytes([0u8; 32]), 0, &wrapper)
            .expect_err("must reject");
        assert!(matches!(
            err,
            MempoolDecryptionError::ShareDecodeFailed { .. }
        ));
    }

    #[test]
    fn accumulator_forget_drops_pending() {
        let (mpk, key_shares, pk_map) = fixture_threshold_setup(3, 5);
        let identity = b"id-forget".to_vec();
        let plaintext = b"forgotten".to_vec();
        let (envelope, _shares) =
            fixture_threshold_envelope(&mpk, &key_shares, &identity, &plaintext);
        let mut acc = ThresholdShareAccumulator::new(pk_map, 3);
        acc.submit_envelope(VertexId::from_bytes([0u8; 32]), 0, envelope)
            .expect("envelope");
        assert_eq!(acc.pending_count(), 1);
        assert!(acc.forget(&identity));
        assert_eq!(acc.pending_count(), 0);
        // Forgetting an unknown identity returns false.
        assert!(!acc.forget(b"never-seen"));
    }

    // ---- Error display ----

    #[test]
    fn mempool_decryption_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<MempoolDecryptionError>();
    }

    #[test]
    fn mempool_decryption_error_display_messages_are_distinct() {
        let variants = vec![
            MempoolDecryptionError::VertexNotInDag(VertexId::from_bytes([0u8; 32])),
            MempoolDecryptionError::EnvelopeDecodeFailed {
                vertex: VertexId::from_bytes([0u8; 32]),
                index: 1,
            },
            MempoolDecryptionError::TimeLockDecryptionFailed {
                vertex: VertexId::from_bytes([0u8; 32]),
                index: 2,
            },
            MempoolDecryptionError::ShareDecodeFailed {
                vertex: VertexId::from_bytes([0u8; 32]),
                index: 3,
            },
            MempoolDecryptionError::ShareVerificationFailed {
                identity: b"a".to_vec(),
                share_index: 1,
            },
            MempoolDecryptionError::UnknownValidatorShareIndex {
                identity: b"a".to_vec(),
                share_index: 2,
            },
            MempoolDecryptionError::CombineFailed {
                identity: b"a".to_vec(),
            },
            MempoolDecryptionError::DecapsulationFailed {
                identity: b"a".to_vec(),
            },
            MempoolDecryptionError::AeadDecryptionFailed {
                identity: b"a".to_vec(),
            },
            MempoolDecryptionError::CiphertextTooShort {
                identity: b"a".to_vec(),
            },
        ];
        let messages: Vec<String> = variants.iter().map(ToString::to_string).collect();
        for m in &messages {
            assert!(!m.is_empty());
        }
        for i in 0..messages.len() {
            for j in (i + 1)..messages.len() {
                assert_ne!(messages[i], messages[j]);
            }
        }
    }

    // ---- DecryptedTransaction BCS ----

    #[test]
    fn decrypted_transaction_bcs_round_trip() {
        let t = DecryptedTransaction {
            origin_vertex: VertexId::from_bytes([0xa1u8; 32]),
            origin_index: 7,
            plaintext: vec![1, 2, 3, 4, 5],
        };
        let bytes = bcs::to_bytes(&t).expect("encode");
        let decoded: DecryptedTransaction = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(t, decoded);
    }
}
