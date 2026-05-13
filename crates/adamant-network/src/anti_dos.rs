//! Anti-denial-of-service primitives per whitepaper §9.5.
//!
//! Phase 7.8.2 deliverable — wires the four §9.5 anti-DoS
//! layers onto the Phase 7.8.0 wire-format types:
//!
//! - §9.5.1 **Submission proofs.** Hashcash-style `PoW`; the
//!   submitter grinds nonces until the SHA3-256 tagged hash
//!   of the transaction body + nonce has at least
//!   `difficulty_bits` leading zero bits. Difficulty is per-
//!   node dynamic; heavily-loaded receivers raise their
//!   minimum-accepted threshold. See [`verify_submission_proof`]
//!   + [`compute_submission_proof`].
//! - §9.5.2 **Fee floors.** Every transaction must pay at least
//!   a per-byte minimum fee. Validators discard sub-floor
//!   transactions without propagating. See [`FeeFloor`].
//! - §9.5.3 **Per-peer rate limiting.** Each node imposes
//!   per-peer rate limits via token-bucket. Peers exceeding
//!   their bucket are throttled or rejected. See
//!   [`RateLimiter`] + [`RateLimitDecision`].
//! - §9.5.4 **Cryptographic verification before propagation.**
//!   Phase 7.8.2 ships the §9.5.1/2/3 primitives; the §9.5.4
//!   signature-and-proof check on the underlying AVM
//!   transaction body crosses into the §6 execution layer
//!   and lands at Phase 7.8.4 + 7.11 integration.
//!
//! # Hashcash construction
//!
//! ```text
//! body_bytes = BCS(NetworkTransaction with submission_proof = None)
//! input      = body_bytes || nonce.to_le_bytes()
//! hash       = sha3_256_tagged(SUBMISSION_PROOF, input)
//! valid      = leading_zero_bits(hash) >= difficulty_bits
//! ```
//!
//! The `submission_proof = None` substitution in the BCS input
//! is what breaks the circular reference (otherwise the proof
//! would have to hash itself). The
//! [`adamant_crypto::domain::SUBMISSION_PROOF`] tag is the
//! consensus-stable namespace anchor; per §3.3.1 adding the
//! tag at Phase 7.8.2 is a hard-fork-aware deliberate change.
//!
//! # Token-bucket rate limiting
//!
//! [`RateLimiter`] uses a per-peer token-bucket with the
//! following semantics:
//!
//! - Each peer starts with `capacity` tokens.
//! - Every submission costs 1 token.
//! - Tokens refill linearly at `refill_per_second` tokens/sec.
//! - When a peer's bucket reaches 0, submissions are
//!   throttled (returned as [`RateLimitDecision::Throttle`]).
//! - When a peer's bucket falls below `-capacity` (sustained
//!   abuse), submissions are rejected outright
//!   ([`RateLimitDecision::Reject`]) — the bookkeeping
//!   continues so the rate limiter can disconnect repeat
//!   offenders at a higher layer.
//!
//! # Anti-DoS orchestrator
//!
//! The [`validate_submission`] function combines
//! [`verify_submission_proof`] + [`FeeFloor::check`].
//! Caller-side rate limiting is intentionally separate
//! (caller decides whether to call [`RateLimiter::check`]
//! before the cryptographic checks, to short-circuit on a
//! known-abusive peer without consuming verification cycles).

use std::collections::HashMap;
use std::time::Duration;

use adamant_crypto::domain;
use adamant_crypto::hash::sha3_256_tagged;
use libp2p::PeerId;
use serde::{Deserialize, Serialize};

use crate::{NetworkTransaction, SubmissionProof};

// ===============================================================
// §9.5.1 Submission proofs
// ===============================================================

/// Maximum permitted `difficulty_bits` value. 64 zero bits
/// would imply ~1.8 × 10¹⁹ expected nonce trials — astronomically
/// beyond the §9.5.1 "50-100ms `PoW` puzzle" target. Capping at 64
/// also keeps the verification hash-comparison logic simple
/// (a 32-byte hash has at most 256 leading-zero-bits structurally,
/// but anything above 64 bits is operationally absurd).
pub const MAX_DIFFICULTY_BITS: u8 = 64;

/// Compute the `PoW` hash for a [`NetworkTransaction`] body plus
/// a candidate nonce. Used internally by
/// [`verify_submission_proof`] and [`compute_submission_proof`].
///
/// Hash construction per the module docs:
/// `sha3_256_tagged(SUBMISSION_PROOF, BCS(tx with submission_proof=None) || nonce_le_bytes)`.
fn compute_pow_hash(tx: &NetworkTransaction, nonce: u64) -> [u8; 32] {
    let body_bytes = bcs_body_without_proof(tx);
    compute_pow_hash_with_body(&body_bytes, nonce)
}

/// BCS-encode a [`NetworkTransaction`] with `submission_proof =
/// None`. Hoisted out of [`compute_pow_hash`] so the
/// [`compute_submission_proof`] grind loop can compute it once
/// and reuse the bytes across every nonce trial (avoiding a
/// per-iteration `tx.clone()` + BCS-encode of the full
/// transaction body, which dominates the hash cost for large
/// payloads).
fn bcs_body_without_proof(tx: &NetworkTransaction) -> Vec<u8> {
    // The closed-form construction without cloning the full tx:
    // build a wire-shape-identical transient that borrows tx's
    // payload + threads None into the submission_proof slot.
    // BCS encodes structs field-by-field, so we serialise each
    // field in declaration order. NetworkTransaction's field
    // order is consensus-pinned (see `network_transaction_field_order_pin`
    // test in lib.rs).
    let body = NetworkTransaction {
        version: tx.version,
        encryption_mode: tx.encryption_mode,
        payload: tx.payload.clone(), // small (payload is the cleartext or ciphertext body)
        fee_tip: tx.fee_tip,
        expiration_round: tx.expiration_round,
        submission_proof: None,
    };
    bcs::to_bytes(&body).expect("NetworkTransaction is BCS-serialisable by construction")
}

/// Compute the `PoW` hash from already-encoded body bytes + a
/// nonce. The hot-path entry: the grind loop encodes the body
/// once, then calls this for every nonce trial.
fn compute_pow_hash_with_body(body_bytes: &[u8], nonce: u64) -> [u8; 32] {
    let mut input = Vec::with_capacity(body_bytes.len() + 8);
    input.extend_from_slice(body_bytes);
    input.extend_from_slice(&nonce.to_le_bytes());
    sha3_256_tagged(&domain::SUBMISSION_PROOF, &input)
}

/// Count the number of leading zero bits in a byte slice (big-
/// endian interpretation). For a SHA3-256 digest (32 bytes),
/// the range is `0..=256`.
fn leading_zero_bits(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for b in bytes {
        if *b == 0 {
            count += 8;
            continue;
        }
        return count + b.leading_zeros();
    }
    count
}

/// Verify a submission proof against a transaction body and a
/// receiver's minimum-difficulty threshold.
///
/// Returns `true` iff:
/// 1. `proof.difficulty_bits >= min_difficulty` (the proof
///    claims to have met the receiver's threshold).
/// 2. `leading_zero_bits(hash) >= proof.difficulty_bits` (the
///    proof actually meets its claimed difficulty).
///
/// Per §9.5.1, the second check is the substantive `PoW`
/// verification; the first check is a fast pre-filter so
/// receivers can reject low-difficulty proofs without
/// performing the hash computation.
///
/// Hash computation is one SHA3-256 of the BCS-encoded
/// transaction body — fast (microseconds) regardless of
/// difficulty.
#[must_use]
pub fn verify_submission_proof(
    tx: &NetworkTransaction,
    proof: &SubmissionProof,
    min_difficulty: u8,
) -> bool {
    if proof.difficulty_bits < min_difficulty {
        return false;
    }
    if proof.difficulty_bits > MAX_DIFFICULTY_BITS {
        return false;
    }
    let hash = compute_pow_hash(tx, proof.nonce);
    leading_zero_bits(&hash) >= u32::from(proof.difficulty_bits)
}

/// Grind for a [`SubmissionProof`] meeting `target_difficulty`
/// over a transaction. Iterates `0..max_iterations` nonces;
/// returns `None` if no solution is found within the budget
/// (rare for sub-20-bit targets at the §9.5.1 calibrated
/// difficulty).
///
/// Honest clients call this once per transaction submission
/// with `target_difficulty` set to the current network-wide
/// expected threshold (discovered via gossip or peer query —
/// the discovery mechanism is operational, not consensus-
/// binding).
///
/// # Caller responsibility
///
/// The caller selects `target_difficulty` ≤
/// [`MAX_DIFFICULTY_BITS`]. The function returns `None` if
/// the target exceeds the cap.
#[must_use]
pub fn compute_submission_proof(
    tx: &NetworkTransaction,
    target_difficulty: u8,
    max_iterations: u64,
) -> Option<SubmissionProof> {
    if target_difficulty > MAX_DIFFICULTY_BITS {
        return None;
    }
    // Encode the body once outside the loop. For a 1 KiB
    // payload at 20-bit difficulty (~1M iterations), this saves
    // ~1 GiB of allocation churn vs encoding per-iteration.
    let body_bytes = bcs_body_without_proof(tx);
    for nonce in 0..max_iterations {
        let hash = compute_pow_hash_with_body(&body_bytes, nonce);
        if leading_zero_bits(&hash) >= u32::from(target_difficulty) {
            return Some(SubmissionProof {
                nonce,
                difficulty_bits: target_difficulty,
            });
        }
    }
    None
}

// ===============================================================
// §9.5.2 Fee floors
// ===============================================================

/// Per-byte fee floor per whitepaper §9.5.2.
///
/// The minimum acceptable `fee_tip` for a transaction is
/// `micro_adm_per_byte * BCS-encoded-size(tx)`. Transactions
/// below this floor are dropped without propagation.
///
/// Per §9.5.2 + §10, the floor is calibrated to make spam
/// economically expensive while remaining negligible for real
/// use. The exact value is set in `adamant-consensus` /
/// `adamant-economics` at pre-mainnet hardening; Phase 7.8.2
/// ships the verification primitive against any value.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct FeeFloor {
    /// Per-byte fee floor in ADM micro-units. 1 ADM = 10⁶
    /// micro-ADM; a typical floor at launch is on the order
    /// of 1-10 micro-ADM/byte (~$0.0001 per ~1 KiB tx per
    /// §2 throughput-floor target).
    pub micro_adm_per_byte: u64,
}

impl FeeFloor {
    /// New floor at `micro_adm_per_byte` micro-ADM per byte.
    #[must_use]
    pub const fn new(micro_adm_per_byte: u64) -> Self {
        Self { micro_adm_per_byte }
    }

    /// Minimum fee required for `tx` under this floor.
    /// Returns `u64::MAX` if the size × per-byte calculation
    /// overflows (defensive; means the transaction is too
    /// large to be acceptable at any tip).
    #[must_use]
    pub fn minimum_for(&self, tx: &NetworkTransaction) -> u64 {
        let size = bcs::serialized_size(tx).map_or(usize::MAX, |s| s);
        // Saturating multiply to handle pathological sizes.
        u64::try_from(size)
            .unwrap_or(u64::MAX)
            .saturating_mul(self.micro_adm_per_byte)
    }

    /// Check `tx.fee_tip >= self.minimum_for(tx)`.
    #[must_use]
    pub fn check(&self, tx: &NetworkTransaction) -> bool {
        tx.fee_tip >= self.minimum_for(tx)
    }
}

// ===============================================================
// §9.5.3 Per-peer rate limiting
// ===============================================================

/// Configuration for a [`RateLimiter`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct RateLimitConfig {
    /// Maximum tokens a peer accumulates. New peers start at
    /// `capacity`; this is also the burst tolerance for a
    /// peer that has been idle long enough for full refill.
    pub capacity: u32,

    /// Tokens refilled per second. The honest steady-state
    /// rate a peer can sustain.
    pub refill_per_second: u32,

    /// Rejection threshold: peers whose token count falls
    /// this far below zero are returned as
    /// [`RateLimitDecision::Reject`] instead of `Throttle`.
    /// Higher values mean more grace before outright reject.
    pub reject_below_negative: u32,
}

impl RateLimitConfig {
    /// Default config: 20-token capacity, 5 tokens/sec refill,
    /// reject at -20 (i.e., a sustained 20-token deficit
    /// after capacity is exhausted). Tunable per node.
    #[must_use]
    pub const fn launch_default() -> Self {
        Self {
            capacity: 20,
            refill_per_second: 5,
            reject_below_negative: 20,
        }
    }
}

/// Decision returned by [`RateLimiter::check`].
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum RateLimitDecision {
    /// Peer is within budget; accept the submission.
    Allow,

    /// Peer has exhausted their bucket but hasn't sustained
    /// the abuse long enough to warrant rejection. Submission
    /// SHOULD be deprioritised or queued; the caller's policy
    /// decides whether to drop it.
    Throttle,

    /// Peer has sustained abuse beyond
    /// [`RateLimitConfig::reject_below_negative`]; drop the
    /// submission outright and consider disconnecting the
    /// peer at the libp2p layer.
    Reject,
}

/// Per-peer state inside the [`RateLimiter`]. Hidden so the
/// rate-limiter's bookkeeping evolves freely.
#[derive(Clone, Copy, Debug)]
struct PeerBucket {
    /// Token count. Stored as `i64` to allow negative values
    /// (sustained-abuse signal); positive values are bounded
    /// by `RateLimitConfig::capacity`.
    tokens: i64,

    /// Microseconds since some monotonic origin at which
    /// `tokens` was last updated. Decouples from system
    /// clock; caller supplies the monotonic time via
    /// `now_micros` in [`RateLimiter::check`].
    last_refill_micros: u64,
}

/// Per-peer rate limiter per whitepaper §9.5.3.
///
/// Token-bucket per peer. Caller supplies monotonic time via
/// `now_micros` in [`Self::check`] — the limiter does not
/// reach into the system clock, which keeps it deterministic
/// for tests and simulator scenarios.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    config: RateLimitConfig,
    peers: HashMap<PeerId, PeerBucket>,
}

impl RateLimiter {
    /// New limiter with the supplied config.
    #[must_use]
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
        }
    }

    /// New limiter with [`RateLimitConfig::launch_default`].
    #[must_use]
    pub fn launch_default() -> Self {
        Self::new(RateLimitConfig::launch_default())
    }

    /// Number of peers the limiter is tracking.
    #[must_use]
    pub fn tracked_peers(&self) -> usize {
        self.peers.len()
    }

    /// The limiter's current configuration.
    #[must_use]
    pub const fn config(&self) -> &RateLimitConfig {
        &self.config
    }

    /// Check whether `peer` may submit at `now_micros`. Charges
    /// 1 token against the peer's bucket and returns the
    /// decision based on post-charge balance.
    pub fn check(&mut self, peer: PeerId, now_micros: u64) -> RateLimitDecision {
        let capacity = i64::from(self.config.capacity);
        let refill_per_sec = i64::from(self.config.refill_per_second);
        let reject_floor = -i64::from(self.config.reject_below_negative);
        let bucket = self.peers.entry(peer).or_insert(PeerBucket {
            tokens: capacity,
            last_refill_micros: now_micros,
        });
        // Refill: tokens += (elapsed_secs * refill_per_sec).
        let elapsed_micros = now_micros.saturating_sub(bucket.last_refill_micros);
        let elapsed_secs = elapsed_micros / 1_000_000;
        let elapsed_secs_i64 = i64::try_from(elapsed_secs).unwrap_or(i64::MAX);
        let refill = elapsed_secs_i64.saturating_mul(refill_per_sec);
        bucket.tokens = bucket.tokens.saturating_add(refill).min(capacity);
        // Only advance the last_refill timestamp by whole-second
        // chunks so sub-second refill progress isn't lost.
        bucket.last_refill_micros = bucket
            .last_refill_micros
            .saturating_add(elapsed_secs.saturating_mul(1_000_000));
        // Charge 1 token for this submission.
        bucket.tokens = bucket.tokens.saturating_sub(1);
        // Decide.
        if bucket.tokens >= 0 {
            RateLimitDecision::Allow
        } else if bucket.tokens >= reject_floor {
            RateLimitDecision::Throttle
        } else {
            RateLimitDecision::Reject
        }
    }

    /// Drop the limiter's state for `peer`. Caller-side
    /// helper for explicit disconnection (the limiter
    /// otherwise retains state indefinitely; honest operators
    /// periodically prune via a background tick).
    pub fn forget(&mut self, peer: &PeerId) -> bool {
        self.peers.remove(peer).is_some()
    }
}

// ===============================================================
// §9.5 orchestrator
// ===============================================================

/// Typed errors produced by [`validate_submission`].
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AntiDosError {
    /// The transaction's `submission_proof` is `None`. Honest
    /// clients always attach a proof; missing-proof
    /// submissions are rejected.
    MissingSubmissionProof,

    /// The submission proof failed §9.5.1 verification — its
    /// claimed difficulty was below `min_difficulty`, OR the
    /// hash actually computed does not meet the claimed
    /// difficulty (forged proof).
    InvalidSubmissionProof {
        /// The receiver's minimum-difficulty threshold at
        /// validation time.
        min_difficulty: u8,
        /// The difficulty the proof claimed to have met.
        claimed_difficulty: u8,
    },

    /// The transaction's `fee_tip` is below the §9.5.2 per-
    /// byte floor.
    BelowFeeFloor {
        /// The fee the transaction offered.
        offered: u64,
        /// The minimum fee required at the current floor.
        required: u64,
    },
}

impl core::fmt::Display for AntiDosError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::MissingSubmissionProof => f.write_str("submission proof missing"),
            Self::InvalidSubmissionProof {
                min_difficulty,
                claimed_difficulty,
            } => write!(
                f,
                "submission proof invalid: min={min_difficulty} claimed={claimed_difficulty}"
            ),
            Self::BelowFeeFloor { offered, required } => {
                write!(f, "fee tip {offered} below floor {required}")
            }
        }
    }
}

impl std::error::Error for AntiDosError {}

/// Orchestrate the §9.5.1 + §9.5.2 checks. Returns `Ok(())`
/// iff the transaction's submission proof verifies against
/// `min_difficulty` AND the fee tip meets the floor.
///
/// Per §9.5.3, per-peer rate limiting is invoked separately
/// by the caller (typically before this function, to short-
/// circuit known-abusive peers without consuming
/// cryptographic verification cycles).
///
/// Per §9.5.4, signature + proof verification on the
/// underlying AVM transaction body crosses into the §6
/// execution layer and lands at Phase 7.8.4 + 7.11
/// integration.
///
/// # Errors
///
/// - [`AntiDosError::MissingSubmissionProof`]
/// - [`AntiDosError::InvalidSubmissionProof`]
/// - [`AntiDosError::BelowFeeFloor`]
pub fn validate_submission(
    tx: &NetworkTransaction,
    fee_floor: &FeeFloor,
    min_difficulty: u8,
) -> Result<(), AntiDosError> {
    let proof = tx
        .submission_proof
        .as_ref()
        .ok_or(AntiDosError::MissingSubmissionProof)?;
    if !verify_submission_proof(tx, proof, min_difficulty) {
        return Err(AntiDosError::InvalidSubmissionProof {
            min_difficulty,
            claimed_difficulty: proof.difficulty_bits,
        });
    }
    let required = fee_floor.minimum_for(tx);
    if tx.fee_tip < required {
        return Err(AntiDosError::BelowFeeFloor {
            offered: tx.fee_tip,
            required,
        });
    }
    Ok(())
}

/// Convert a [`Duration`] into microseconds-since-some-monotonic-
/// origin, saturating at `u64::MAX`. Helper for callers using
/// `std::time::Instant::elapsed()` to drive
/// [`RateLimiter::check`].
#[must_use]
pub fn duration_to_micros(d: Duration) -> u64 {
    u64::try_from(d.as_micros()).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_consensus::RoundNumber;

    fn fixture_tx() -> NetworkTransaction {
        NetworkTransaction::transparent(1, vec![1, 2, 3, 4, 5], 100, RoundNumber::new(42))
    }

    // ---- Submission proof ----

    #[test]
    fn max_difficulty_bits_pinned_at_64() {
        assert_eq!(MAX_DIFFICULTY_BITS, 64);
    }

    #[test]
    fn leading_zero_bits_known_inputs() {
        assert_eq!(leading_zero_bits(&[0xFFu8, 0x00]), 0);
        assert_eq!(leading_zero_bits(&[0x80u8, 0x00]), 0);
        assert_eq!(leading_zero_bits(&[0x40u8, 0x00]), 1);
        assert_eq!(leading_zero_bits(&[0x01u8, 0x00]), 7);
        assert_eq!(leading_zero_bits(&[0x00u8, 0xFF]), 8);
        assert_eq!(leading_zero_bits(&[0x00u8, 0x80]), 8);
        assert_eq!(leading_zero_bits(&[0x00u8, 0x40]), 9);
        assert_eq!(leading_zero_bits(&[0x00u8; 4]), 32);
    }

    #[test]
    fn compute_submission_proof_returns_some_for_low_difficulty() {
        let tx = fixture_tx();
        // At 4 bits, expected ~16 trials; max=10_000 budget is
        // comfortable.
        let proof = compute_submission_proof(&tx, 4, 10_000).expect("low difficulty solvable");
        assert!(proof.difficulty_bits >= 4);
        // The proof's hash actually meets the difficulty.
        assert!(verify_submission_proof(&tx, &proof, 4));
    }

    #[test]
    fn compute_submission_proof_returns_none_above_max_difficulty() {
        let tx = fixture_tx();
        let proof = compute_submission_proof(&tx, MAX_DIFFICULTY_BITS + 1, 1);
        assert!(proof.is_none());
    }

    #[test]
    fn verify_submission_proof_rejects_below_min_difficulty() {
        let tx = fixture_tx();
        let proof = compute_submission_proof(&tx, 4, 10_000).expect("solve");
        // Receiver demanding 8 bits but proof is at 4.
        assert!(!verify_submission_proof(&tx, &proof, 8));
    }

    #[test]
    fn verify_submission_proof_rejects_proof_above_max_difficulty() {
        let tx = fixture_tx();
        // Forge a proof claiming impossible difficulty.
        let proof = SubmissionProof::new(0, MAX_DIFFICULTY_BITS + 1);
        assert!(!verify_submission_proof(&tx, &proof, 0));
    }

    #[test]
    fn verify_submission_proof_rejects_forged_proof() {
        // A nonce that almost certainly doesn't hash to many
        // leading zeros at 16 bits.
        let tx = fixture_tx();
        let proof = SubmissionProof::new(0xDEAD_BEEF, 16);
        // The verifier checks the hash itself; the forgery
        // won't survive.
        assert!(!verify_submission_proof(&tx, &proof, 16));
    }

    #[test]
    fn verify_submission_proof_is_deterministic() {
        let tx = fixture_tx();
        let proof = compute_submission_proof(&tx, 4, 10_000).expect("solve");
        for _ in 0..3 {
            assert!(verify_submission_proof(&tx, &proof, 4));
        }
    }

    #[test]
    fn proof_for_one_tx_does_not_verify_for_another() {
        let tx_a = fixture_tx();
        let mut tx_b = fixture_tx();
        tx_b.payload = vec![9, 9, 9, 9, 9];
        let proof_a = compute_submission_proof(&tx_a, 4, 10_000).expect("solve");
        // Same proof structure won't verify against tx_b
        // (hash input differs).
        assert!(!verify_submission_proof(&tx_b, &proof_a, 4));
    }

    // ---- Fee floor ----

    #[test]
    fn fee_floor_new_and_check() {
        let floor = FeeFloor::new(2);
        let tx = NetworkTransaction::transparent(1, vec![0u8; 100], 1000, RoundNumber::new(0));
        let minimum = floor.minimum_for(&tx);
        // 2 micro-ADM/byte × (header + 100-byte payload) ~= 2 * 100+ bytes.
        assert!(minimum > 0);
        assert!(floor.check(&tx));
        let cheap_tx = NetworkTransaction::transparent(1, vec![0u8; 100], 1, RoundNumber::new(0));
        assert!(!floor.check(&cheap_tx));
    }

    #[test]
    fn fee_floor_zero_accepts_everything() {
        let floor = FeeFloor::new(0);
        let tx = NetworkTransaction::transparent(1, vec![0u8; 10], 0, RoundNumber::new(0));
        assert!(floor.check(&tx));
        assert_eq!(floor.minimum_for(&tx), 0);
    }

    #[test]
    fn fee_floor_bcs_round_trip() {
        let floor = FeeFloor::new(7);
        let bytes = bcs::to_bytes(&floor).expect("encode");
        let decoded: FeeFloor = bcs::from_bytes(&bytes).expect("decode");
        assert_eq!(floor, decoded);
    }

    // ---- Rate limiter ----

    #[test]
    fn rate_limit_config_launch_default_values() {
        let cfg = RateLimitConfig::launch_default();
        assert_eq!(cfg.capacity, 20);
        assert_eq!(cfg.refill_per_second, 5);
        assert_eq!(cfg.reject_below_negative, 20);
    }

    #[test]
    fn rate_limiter_first_request_allows() {
        let mut rl = RateLimiter::launch_default();
        let peer = PeerId::random();
        assert_eq!(rl.check(peer, 0), RateLimitDecision::Allow);
        assert_eq!(rl.tracked_peers(), 1);
    }

    #[test]
    fn rate_limiter_exhausts_capacity_then_throttles() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            capacity: 3,
            refill_per_second: 1,
            reject_below_negative: 5,
        });
        let peer = PeerId::random();
        // 3 allows.
        assert_eq!(rl.check(peer, 0), RateLimitDecision::Allow);
        assert_eq!(rl.check(peer, 0), RateLimitDecision::Allow);
        assert_eq!(rl.check(peer, 0), RateLimitDecision::Allow);
        // 4th: tokens = -1 → Throttle.
        assert_eq!(rl.check(peer, 0), RateLimitDecision::Throttle);
    }

    #[test]
    fn rate_limiter_reject_after_sustained_abuse() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            capacity: 2,
            refill_per_second: 1,
            reject_below_negative: 3,
        });
        let peer = PeerId::random();
        // 2 allows.
        assert_eq!(rl.check(peer, 0), RateLimitDecision::Allow);
        assert_eq!(rl.check(peer, 0), RateLimitDecision::Allow);
        // Then -1, -2, -3 → Throttle.
        for _ in 0..3 {
            assert_eq!(rl.check(peer, 0), RateLimitDecision::Throttle);
        }
        // -4 < -3 (reject_below_negative) → Reject.
        assert_eq!(rl.check(peer, 0), RateLimitDecision::Reject);
    }

    #[test]
    fn rate_limiter_refills_over_time() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            capacity: 5,
            refill_per_second: 1,
            reject_below_negative: 10,
        });
        let peer = PeerId::random();
        for _ in 0..5 {
            rl.check(peer, 0);
        }
        // Tokens at 0; one more brings to -1.
        assert_eq!(rl.check(peer, 0), RateLimitDecision::Throttle);
        // After 3 seconds, +3 refill → 2 tokens.
        assert_eq!(rl.check(peer, 3 * 1_000_000), RateLimitDecision::Allow);
        assert_eq!(rl.check(peer, 3 * 1_000_000), RateLimitDecision::Allow);
        // One more → 0, then negative.
        assert_eq!(rl.check(peer, 3 * 1_000_000), RateLimitDecision::Throttle);
    }

    #[test]
    fn rate_limiter_refill_capped_at_capacity() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            capacity: 3,
            refill_per_second: 1,
            reject_below_negative: 10,
        });
        let peer = PeerId::random();
        rl.check(peer, 0); // -> 2 tokens
                           // After 10 seconds, refill of 10 but capped at 3.
                           // Then 3 checks succeed; 4th throttles.
        for _ in 0..3 {
            assert_eq!(rl.check(peer, 10 * 1_000_000), RateLimitDecision::Allow);
        }
        assert_eq!(rl.check(peer, 10 * 1_000_000), RateLimitDecision::Throttle);
    }

    #[test]
    fn rate_limiter_per_peer_isolation() {
        let mut rl = RateLimiter::new(RateLimitConfig {
            capacity: 1,
            refill_per_second: 1,
            reject_below_negative: 5,
        });
        let alice = PeerId::random();
        let bob = PeerId::random();
        assert_eq!(rl.check(alice, 0), RateLimitDecision::Allow);
        // Alice exhausted; Bob still fresh.
        assert_eq!(rl.check(alice, 0), RateLimitDecision::Throttle);
        assert_eq!(rl.check(bob, 0), RateLimitDecision::Allow);
    }

    #[test]
    fn rate_limiter_forget_removes_state() {
        let mut rl = RateLimiter::launch_default();
        let peer = PeerId::random();
        rl.check(peer, 0);
        assert_eq!(rl.tracked_peers(), 1);
        assert!(rl.forget(&peer));
        assert_eq!(rl.tracked_peers(), 0);
        assert!(!rl.forget(&peer));
    }

    // ---- Orchestrator ----

    #[test]
    fn validate_submission_happy_path() {
        let mut tx = fixture_tx();
        tx.fee_tip = 10_000;
        let proof = compute_submission_proof(&tx, 4, 10_000).expect("solve");
        tx = tx.with_submission_proof(proof);
        let floor = FeeFloor::new(0); // no fee floor
        assert!(validate_submission(&tx, &floor, 4).is_ok());
    }

    #[test]
    fn validate_submission_rejects_missing_proof() {
        let tx = fixture_tx(); // no submission_proof
        let floor = FeeFloor::new(0);
        let err = validate_submission(&tx, &floor, 0).expect_err("must reject");
        assert_eq!(err, AntiDosError::MissingSubmissionProof);
    }

    #[test]
    fn validate_submission_rejects_low_difficulty_proof() {
        let mut tx = fixture_tx();
        let proof = compute_submission_proof(&tx, 4, 10_000).expect("solve");
        tx = tx.with_submission_proof(proof);
        let floor = FeeFloor::new(0);
        let err = validate_submission(&tx, &floor, 12).expect_err("must reject");
        assert!(matches!(err, AntiDosError::InvalidSubmissionProof { .. }));
    }

    #[test]
    fn validate_submission_rejects_below_fee_floor() {
        let mut tx = fixture_tx();
        tx.fee_tip = 0;
        let proof = compute_submission_proof(&tx, 4, 10_000).expect("solve");
        tx = tx.with_submission_proof(proof);
        let floor = FeeFloor::new(100); // floor of 100 per byte
        let err = validate_submission(&tx, &floor, 4).expect_err("must reject");
        assert!(matches!(err, AntiDosError::BelowFeeFloor { .. }));
    }

    // ---- AntiDosError ----

    #[test]
    fn anti_dos_error_display_messages_are_distinct() {
        let variants = [
            AntiDosError::MissingSubmissionProof,
            AntiDosError::InvalidSubmissionProof {
                min_difficulty: 4,
                claimed_difficulty: 2,
            },
            AntiDosError::BelowFeeFloor {
                offered: 1,
                required: 100,
            },
        ];
        let msgs: Vec<String> = variants.iter().map(ToString::to_string).collect();
        for m in &msgs {
            assert!(!m.is_empty());
        }
        for i in 0..msgs.len() {
            for j in (i + 1)..msgs.len() {
                assert_ne!(msgs[i], msgs[j]);
            }
        }
    }

    #[test]
    fn anti_dos_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<AntiDosError>();
    }

    // ---- Helpers ----

    #[test]
    fn duration_to_micros_round_trip() {
        let d = Duration::from_secs(7);
        assert_eq!(duration_to_micros(d), 7_000_000);
        assert_eq!(duration_to_micros(Duration::ZERO), 0);
    }
}
