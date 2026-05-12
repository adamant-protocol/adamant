//! Threshold-encrypted mempool with two-regime hysteresis per
//! whitepaper §3.6 + §8.4 + §3.8.5.
//!
//! Phase 7.6 deliverable. The mempool layer ships the
//! encryption-regime selector + wire types for both the
//! time-lock regime (low-N period) and the threshold regime
//! (steady-state). The §8.4 regime selection is consensus-
//! state-binding: every node must agree on which regime is
//! active at any given epoch, so the regime is part of the
//! per-epoch consensus state and transitions only at epoch
//! boundaries per §8.4.4 + §3.8.5.
//!
//! # Spec basis
//!
//! Whitepaper §8.4 (Encrypted mempool):
//!
//! - §8.4.1 establishes the two-regime structure (threshold at
//!   design-target validator counts; time-lock at low-N).
//! - §8.4.2 specifies the viability boundary at `N = 15`.
//! - §8.4.3 (Threshold regime) covers DKG, encryption to the
//!   epoch threshold key, and decryption-share aggregation.
//! - §8.4.4 (Time-lock regime) covers anchor rotation +
//!   decryption-publication binding.
//! - §3.8.5 (Transition to threshold encryption) specifies the
//!   hysteresis rule: switch to threshold at `N ≥ 15`; switch
//!   back to time-lock at `N < 10`. The `[10, 14]` band keeps
//!   the previous regime.
//!
//! # Phase 7.6 scope
//!
//! - [`Regime`] — the closed enum of regimes (`TimeLock`,
//!   `Threshold`) with consensus-binding BCS variant tags.
//! - [`RegimeState`] — the current regime carried in consensus
//!   state across epoch boundaries.
//! - [`RegimeState::transition`] — applies the §3.8.5
//!   hysteresis rule given the active-set size at an epoch
//!   boundary.
//! - [`ThresholdMempoolEnvelope`] — wire type for §8.4.3
//!   threshold-encrypted envelopes. Parallels
//!   [`adamant_crypto::vdf::TimeLockEnvelope`] from Phase 7.5.
//! - [`MempoolEnvelope`] — closed enum wrapping either regime's
//!   envelope, used as the canonical envelope-on-the-wire shape
//!   the §8.3 DAG vertex's `transactions` field carries.
//!
//! # What this module ships at Phase 7.6
//!
//! Pure wire types + the state-machine arithmetic. Actual
//! encryption / decryption flows for the threshold regime
//! (analog of `adamant_crypto::vdf::envelope::encrypt`) require
//! per-epoch DKG state (§8.4.3 step 1) which lands at the §8.3
//! DAG-BFT integration sub-arc (Phase 7.7); time-lock
//! encryption is already wired through `adamant_crypto::vdf::envelope`
//! from Phase 7.5.4. Phase 7.6 here is the consensus-state-
//! binding type foundation that 7.7 + 7.8 build on.
//!
//! # Boundary constants
//!
//! Both constants are consensus-binding per §8.4.2 + §3.8.5.
//! Changing either is a hard fork.
//!
//! - [`THRESHOLD_ACTIVATION_FLOOR`] = 15 (`N ≥ 15` activates
//!   threshold)
//! - [`THRESHOLD_DEACTIVATION_FLOOR`] = 10 (`N < 10` reverts to
//!   time-lock)

use adamant_crypto::vdf::TimeLockEnvelope;
use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

/// Active-set size at and above which the chain operates the
/// threshold regime per whitepaper §8.4.2 viability boundary.
///
/// At `N < 15` the threshold scheme cannot be parameterised to
/// provide meaningful security (the honest-threshold count `t`
/// would be too low against plausible Byzantine fractions).
/// The §8.4.2 viability boundary aligns with the §8.1.7
/// Tier I → Tier II security-tier boundary: both transitions
/// happen at the same `N`.
///
/// Consensus-binding per §8.4.2; changing this constant is a
/// hard fork.
pub const THRESHOLD_ACTIVATION_FLOOR: usize = 15;

/// Active-set size below which the chain reverts to the
/// time-lock regime per whitepaper §3.8.5 hysteresis rule.
///
/// The gap `[10, 14]` is the hysteresis band: in this range the
/// chain keeps whichever regime was active prior. The band
/// prevents flapping at the boundary if `N` oscillates near
/// `15`.
///
/// Consensus-binding per §3.8.5; changing this constant is a
/// hard fork.
pub const THRESHOLD_DEACTIVATION_FLOOR: usize = 10;

/// The mempool encryption regime in effect at an epoch boundary.
///
/// Closed enum: adding a variant is a consensus rule change.
/// BCS variant tags are pinned (`TimeLock = 0x00`,
/// `Threshold = 0x01`); reordering or renaming is a hard fork
/// per §8.4.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Regime {
    /// Low-N regime per §8.4.4: users encrypt to a Wesolowski
    /// time-lock VDF puzzle; the round anchor decrypts after
    /// `T` sequential squarings. Used when `N < 15` (or in the
    /// `[10, 14]` hysteresis band when arriving from the
    /// time-lock side).
    TimeLock,

    /// Steady-state regime per §8.4.3: users encrypt to the
    /// epoch threshold key; validators publish decryption shares
    /// that aggregate after ordering commits. Used when
    /// `N ≥ 15` (or in the `[10, 14]` hysteresis band when
    /// arriving from the threshold side).
    Threshold,
}

/// Consensus-state-binding wrapper around the currently-active
/// [`Regime`], carrying the regime across epoch boundaries.
///
/// The wrapper exists separately from `Regime` itself because the
/// chain's consensus state per §8.4 tracks the regime — adding
/// future fields (e.g., `last_transition_epoch: EpochNumber`)
/// would extend `RegimeState` without changing the underlying
/// regime enum's BCS encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct RegimeState {
    /// The currently-active regime.
    pub current: Regime,
}

impl RegimeState {
    /// Constructs an initial regime state. Per §8.1.6 the chain
    /// activates at the [`ACTIVE_SET_FLOOR`] of 7 validators, so
    /// the initial regime is always `TimeLock` (since `7 < 15`).
    #[must_use]
    pub const fn at_activation() -> Self {
        Self {
            current: Regime::TimeLock,
        }
    }

    /// Constructs a regime state with the supplied current regime.
    /// Used for consensus-state replay / restoration from chain
    /// state.
    #[must_use]
    pub const fn new(current: Regime) -> Self {
        Self { current }
    }

    /// Applies the §3.8.5 hysteresis rule to compute the regime
    /// for the next epoch given the active-set size at the
    /// current epoch boundary.
    ///
    /// Rule:
    ///
    /// - If currently `TimeLock` and `active_set_size ≥ 15`:
    ///   switch to `Threshold`.
    /// - If currently `Threshold` and `active_set_size < 10`:
    ///   switch back to `TimeLock`.
    /// - Otherwise (including the hysteresis band `[10, 14]`):
    ///   keep the current regime.
    ///
    /// The returned `RegimeState` is the consensus-state input
    /// for the next epoch. Mempool encryption uses
    /// `self.current` (the regime active during the epoch the
    /// transaction is submitted in); the transition takes effect
    /// at the next epoch boundary per §3.8.5 + §8.4.3.
    #[must_use]
    pub fn transition(self, active_set_size: usize) -> Self {
        let next = match self.current {
            Regime::TimeLock if active_set_size >= THRESHOLD_ACTIVATION_FLOOR => Regime::Threshold,
            Regime::Threshold if active_set_size < THRESHOLD_DEACTIVATION_FLOOR => Regime::TimeLock,
            _ => self.current,
        };
        Self { current: next }
    }
}

impl Default for RegimeState {
    fn default() -> Self {
        Self::at_activation()
    }
}

/// Wire type for §8.4.3 threshold-encrypted mempool envelopes.
///
/// Parallels [`adamant_crypto::vdf::TimeLockEnvelope`] from
/// Phase 7.5: a user-submitted ciphertext payload that the
/// chain decrypts at consensus time (here via quorum decryption-
/// share aggregation per §8.4.3 step 2, vs the time-lock regime
/// where a single anchor performs `T` sequential squarings per
/// §8.4.4).
///
/// # Fields
///
/// - `identity` — the per-envelope identity used as the §3.6
///   threshold-encryption KEM identity. Typically a 32-byte
///   value derived from `(transaction_hash, envelope_index)` or
///   similar consensus-context-bound seed.
/// - `ciphertext_header` — the 96-byte threshold-KEM ciphertext
///   header (`adamant_crypto::threshold::CIPHERTEXT_HEADER_BYTES`).
/// - `ciphertext` — the ChaCha20-Poly1305 symmetric ciphertext
///   under the §3.6 KDF-derived key, with the 12-byte
///   ChaCha20-Poly1305 nonce prefixed inline (same layout as
///   [`adamant_crypto::vdf::TimeLockEnvelope::ciphertext`]).
///
/// # Phase 7.6 — wire surface only
///
/// This type carries the BCS-stable wire format. The user-side
/// encryption + validator-side decryption operations land at
/// the §8.3 DAG-BFT integration sub-arc (Phase 7.7) when the
/// per-epoch DKG state is wired in.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ThresholdMempoolEnvelope {
    /// Per-envelope identity for the §3.6 threshold KEM.
    pub identity: Vec<u8>,

    /// 96-byte threshold-KEM ciphertext header per §3.6.1.
    #[serde(with = "BigArray")]
    pub ciphertext_header: [u8; THRESHOLD_CIPHERTEXT_HEADER_BYTES],

    /// ChaCha20-Poly1305 ciphertext under the §3.6-derived key.
    /// Wire layout: `nonce_12 || aead_body` (same as
    /// [`adamant_crypto::vdf::TimeLockEnvelope::ciphertext`]).
    pub ciphertext: Vec<u8>,
}

/// Byte width of the threshold-KEM ciphertext header per §3.6.1.
///
/// Matches `adamant_crypto::threshold::CIPHERTEXT_HEADER_BYTES`
/// (96 bytes). Re-exported here for visibility from the mempool
/// module without requiring downstream consumers to look up the
/// crypto-layer constant.
pub const THRESHOLD_CIPHERTEXT_HEADER_BYTES: usize =
    adamant_crypto::threshold::CIPHERTEXT_HEADER_BYTES;

/// The canonical mempool envelope shape: either a time-lock
/// envelope (when the regime is [`Regime::TimeLock`]) or a
/// threshold envelope (when the regime is [`Regime::Threshold`]).
///
/// Closed enum: adding a variant is a consensus rule change.
/// BCS variant tags are pinned (`TimeLock = 0x00`,
/// `Threshold = 0x01`); reordering or renaming is a hard fork
/// per §8.4.
///
/// The variant must match the regime active at the epoch the
/// envelope was submitted in. Per §3.8.5 "pending time-lock-
/// encrypted transactions submitted before the transition
/// complete decryption normally; new transactions submitted
/// after the transition use the threshold key" — the chain
/// MUST accept both variants during a transition epoch but
/// reject any variant submitted under a non-matching regime
/// (e.g., a `Threshold` variant when the current regime is
/// `TimeLock`, except as a leftover from the prior regime).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum MempoolEnvelope {
    /// Time-lock envelope per §3.8 / Phase 7.5.
    TimeLock(TimeLockEnvelope),

    /// Threshold envelope per §3.6 / §8.4.3.
    Threshold(ThresholdMempoolEnvelope),
}

impl MempoolEnvelope {
    /// Returns the [`Regime`] the envelope was encrypted under.
    /// Useful for caller-side dispatch on which decryption path
    /// to follow.
    #[must_use]
    pub const fn regime(&self) -> Regime {
        match self {
            Self::TimeLock(_) => Regime::TimeLock,
            Self::Threshold(_) => Regime::Threshold,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_crypto::vdf::{ClassGroupElement, WesolowskiProof};

    // ---- Constant pins ----

    #[test]
    fn threshold_activation_floor_pinned_at_15() {
        // §8.4.2 viability boundary. Consensus-binding.
        assert_eq!(THRESHOLD_ACTIVATION_FLOOR, 15);
    }

    #[test]
    fn threshold_deactivation_floor_pinned_at_10() {
        // §3.8.5 hysteresis floor. Consensus-binding.
        assert_eq!(THRESHOLD_DEACTIVATION_FLOOR, 10);
    }

    /// Sanity: hysteresis only makes sense when the
    /// deactivation floor is strictly below the activation
    /// floor, giving a band `[deactivation, activation - 1]`.
    /// Compile-time assertion — if the constants ever drift to
    /// violate the invariant, the build fails.
    const _DEACTIVATION_BELOW_ACTIVATION: () =
        assert!(THRESHOLD_DEACTIVATION_FLOOR < THRESHOLD_ACTIVATION_FLOOR);

    /// Compile-time pin: the deactivation floor must be above
    /// [`crate::active_set::ACTIVE_SET_FLOOR`] (7), because below
    /// the active-set floor the chain is dormant (§8.7.1) and
    /// regime selection is moot. The hysteresis band sits
    /// comfortably above the dormancy threshold.
    const _DEACTIVATION_ABOVE_ACTIVE_SET_FLOOR: () =
        assert!(THRESHOLD_DEACTIVATION_FLOOR > crate::active_set::ACTIVE_SET_FLOOR);

    #[test]
    fn threshold_cipher_header_bytes_matches_crypto_layer() {
        // Pin the cross-layer constant. If
        // adamant_crypto::threshold::CIPHERTEXT_HEADER_BYTES
        // ever changes, this test surfaces the drift.
        assert_eq!(
            THRESHOLD_CIPHERTEXT_HEADER_BYTES,
            adamant_crypto::threshold::CIPHERTEXT_HEADER_BYTES
        );
        assert_eq!(THRESHOLD_CIPHERTEXT_HEADER_BYTES, 96);
    }

    // ---- Regime BCS variant tags ----

    #[test]
    fn regime_bcs_variant_tags_pinned() {
        // Pin the BCS variant tags: TimeLock = 0x00, Threshold = 0x01.
        // Reordering would be a consensus-breaking change.
        let timelock_bytes = bcs::to_bytes(&Regime::TimeLock).expect("serialise");
        assert_eq!(timelock_bytes, vec![0x00]);
        let threshold_bytes = bcs::to_bytes(&Regime::Threshold).expect("serialise");
        assert_eq!(threshold_bytes, vec![0x01]);
    }

    #[test]
    fn regime_bcs_round_trip() {
        for r in [Regime::TimeLock, Regime::Threshold] {
            let bytes = bcs::to_bytes(&r).expect("serialise");
            let recovered: Regime = bcs::from_bytes(&bytes).expect("deserialise");
            assert_eq!(r, recovered);
        }
    }

    // ---- RegimeState ----

    #[test]
    fn regime_state_at_activation_is_time_lock() {
        // §8.1.6 + §8.4.2: chain activates at N = 7 with TimeLock
        // (since 7 < 15).
        let state = RegimeState::at_activation();
        assert_eq!(state.current, Regime::TimeLock);
    }

    #[test]
    fn regime_state_default_is_at_activation() {
        assert_eq!(RegimeState::default(), RegimeState::at_activation());
    }

    #[test]
    fn regime_state_new_carries_arbitrary_regime() {
        let s = RegimeState::new(Regime::Threshold);
        assert_eq!(s.current, Regime::Threshold);
    }

    #[test]
    fn regime_state_bcs_round_trip() {
        for r in [Regime::TimeLock, Regime::Threshold] {
            let state = RegimeState::new(r);
            let bytes = bcs::to_bytes(&state).expect("serialise");
            let recovered: RegimeState = bcs::from_bytes(&bytes).expect("deserialise");
            assert_eq!(state, recovered);
        }
    }

    // ---- Hysteresis transition rules ----

    #[test]
    fn transition_time_lock_below_activation_stays_time_lock() {
        // Below N=15, TimeLock stays TimeLock.
        let state = RegimeState::new(Regime::TimeLock);
        for n in [7, 8, 9, 10, 11, 12, 13, 14] {
            assert_eq!(
                state.transition(n).current,
                Regime::TimeLock,
                "TimeLock should stay at N={n}"
            );
        }
    }

    #[test]
    fn transition_time_lock_at_activation_floor_switches_to_threshold() {
        // N = 15 triggers the switch.
        let state = RegimeState::new(Regime::TimeLock);
        assert_eq!(
            state.transition(15).current,
            Regime::Threshold,
            "TimeLock should switch to Threshold at N=15"
        );
    }

    #[test]
    fn transition_time_lock_above_activation_floor_switches_to_threshold() {
        let state = RegimeState::new(Regime::TimeLock);
        for n in [15, 16, 20, 29, 30, 75, 100, 1000] {
            assert_eq!(
                state.transition(n).current,
                Regime::Threshold,
                "TimeLock should switch to Threshold at N={n}"
            );
        }
    }

    #[test]
    fn transition_threshold_at_deactivation_floor_stays_threshold() {
        // N = 10 keeps Threshold (hysteresis band includes 10).
        // The rule is "switch back at N < 10", so N = 10 does NOT
        // switch back.
        let state = RegimeState::new(Regime::Threshold);
        assert_eq!(
            state.transition(10).current,
            Regime::Threshold,
            "Threshold should stay at N=10 (hysteresis band)"
        );
    }

    #[test]
    fn transition_threshold_in_hysteresis_band_stays_threshold() {
        // Threshold persists in [10, 14] when arriving from above.
        let state = RegimeState::new(Regime::Threshold);
        for n in [10, 11, 12, 13, 14] {
            assert_eq!(
                state.transition(n).current,
                Regime::Threshold,
                "Threshold should stay in hysteresis band at N={n}"
            );
        }
    }

    #[test]
    fn transition_threshold_below_deactivation_floor_switches_to_time_lock() {
        // N < 10 triggers the switch back.
        let state = RegimeState::new(Regime::Threshold);
        for n in [7, 8, 9] {
            assert_eq!(
                state.transition(n).current,
                Regime::TimeLock,
                "Threshold should switch to TimeLock at N={n}"
            );
        }
    }

    #[test]
    fn transition_threshold_at_or_above_activation_floor_stays_threshold() {
        let state = RegimeState::new(Regime::Threshold);
        for n in [15, 16, 30, 75, 1000] {
            assert_eq!(
                state.transition(n).current,
                Regime::Threshold,
                "Threshold should stay at N={n}"
            );
        }
    }

    /// Pin the exact transition matrix for the boundary +
    /// surrounding values to document the §3.8.5 hysteresis rule
    /// in one place.
    #[test]
    fn hysteresis_transition_matrix() {
        let matrix = [
            // (current, N, expected_next)
            (Regime::TimeLock, 7, Regime::TimeLock),
            (Regime::TimeLock, 9, Regime::TimeLock),
            (Regime::TimeLock, 10, Regime::TimeLock),
            (Regime::TimeLock, 14, Regime::TimeLock),
            (Regime::TimeLock, 15, Regime::Threshold), // activation
            (Regime::TimeLock, 100, Regime::Threshold),
            (Regime::Threshold, 100, Regime::Threshold),
            (Regime::Threshold, 15, Regime::Threshold),
            (Regime::Threshold, 14, Regime::Threshold), // hysteresis band
            (Regime::Threshold, 10, Regime::Threshold), // hysteresis band (inclusive)
            (Regime::Threshold, 9, Regime::TimeLock),   // deactivation
            (Regime::Threshold, 7, Regime::TimeLock),
        ];
        for (current, n, expected) in matrix {
            let result = RegimeState::new(current).transition(n).current;
            assert_eq!(
                result, expected,
                "regime {current:?} + N={n} should transition to {expected:?}, got {result:?}",
            );
        }
    }

    #[test]
    fn hysteresis_no_flap_around_boundary() {
        // Property: starting from TimeLock at N=14, then N=15
        // (switch up), then N=14 (stay — hysteresis), then N=10
        // (stay), then N=9 (switch down). The chain spends time
        // in BOTH regimes correctly across the boundary.
        let s0 = RegimeState::new(Regime::TimeLock);
        let s1 = s0.transition(14);
        assert_eq!(s1.current, Regime::TimeLock);
        let s2 = s1.transition(15);
        assert_eq!(s2.current, Regime::Threshold);
        let s3 = s2.transition(14);
        assert_eq!(s3.current, Regime::Threshold);
        let s4 = s3.transition(10);
        assert_eq!(s4.current, Regime::Threshold);
        let s5 = s4.transition(9);
        assert_eq!(s5.current, Regime::TimeLock);
    }

    #[test]
    fn transition_is_idempotent_at_steady_state() {
        // Once in a regime away from the boundaries, repeated
        // transitions with the same N must produce the same
        // result.
        let s = RegimeState::new(Regime::Threshold);
        let after = s.transition(50);
        let after_after = after.transition(50);
        assert_eq!(after, after_after);

        let s = RegimeState::new(Regime::TimeLock);
        let after = s.transition(7);
        let after_after = after.transition(7);
        assert_eq!(after, after_after);
    }

    // ---- ThresholdMempoolEnvelope ----

    fn fixture_threshold_envelope() -> ThresholdMempoolEnvelope {
        ThresholdMempoolEnvelope {
            identity: vec![0xAA; 32],
            ciphertext_header: [0x55; THRESHOLD_CIPHERTEXT_HEADER_BYTES],
            ciphertext: vec![0xBB; 16],
        }
    }

    #[test]
    fn threshold_mempool_envelope_bcs_round_trip() {
        let envelope = fixture_threshold_envelope();
        let bytes = bcs::to_bytes(&envelope).expect("serialise");
        let recovered: ThresholdMempoolEnvelope = bcs::from_bytes(&bytes).expect("deserialise");
        assert_eq!(envelope, recovered);
    }

    #[test]
    fn threshold_mempool_envelope_ciphertext_header_width_pinned() {
        // The header is a fixed 96-byte array — BCS encodes it
        // inline (no length prefix). Confirm the encoded width.
        let envelope = ThresholdMempoolEnvelope {
            identity: vec![],           // BCS: ULEB128(0) = 0x00
            ciphertext_header: [0; 96], // BCS: 96 raw bytes
            ciphertext: vec![],         // BCS: ULEB128(0) = 0x00
        };
        let bytes = bcs::to_bytes(&envelope).expect("serialise");
        // 1 (identity len prefix) + 96 (header) + 1 (ciphertext len prefix) = 98
        assert_eq!(bytes.len(), 98);
    }

    // ---- MempoolEnvelope ----

    fn fixture_time_lock_envelope() -> TimeLockEnvelope {
        TimeLockEnvelope {
            puzzle: ClassGroupElement::from_bytes(vec![0x11; 16]),
            ciphertext: vec![0x22; 32],
            well_formedness_proof: WesolowskiProof {
                pi: ClassGroupElement::from_bytes(vec![0x33; 16]),
            },
        }
    }

    #[test]
    fn mempool_envelope_bcs_variant_tags_pinned() {
        // TimeLock = 0x00, Threshold = 0x01. Reordering is a
        // consensus-breaking change.
        let time_lock_env = MempoolEnvelope::TimeLock(fixture_time_lock_envelope());
        let threshold_env = MempoolEnvelope::Threshold(fixture_threshold_envelope());
        let time_lock_bytes = bcs::to_bytes(&time_lock_env).expect("serialise");
        let threshold_bytes = bcs::to_bytes(&threshold_env).expect("serialise");
        assert_eq!(time_lock_bytes[0], 0x00);
        assert_eq!(threshold_bytes[0], 0x01);
    }

    #[test]
    fn mempool_envelope_bcs_round_trip_time_lock() {
        let envelope = MempoolEnvelope::TimeLock(fixture_time_lock_envelope());
        let bytes = bcs::to_bytes(&envelope).expect("serialise");
        let recovered: MempoolEnvelope = bcs::from_bytes(&bytes).expect("deserialise");
        assert_eq!(envelope, recovered);
    }

    #[test]
    fn mempool_envelope_bcs_round_trip_threshold() {
        let envelope = MempoolEnvelope::Threshold(fixture_threshold_envelope());
        let bytes = bcs::to_bytes(&envelope).expect("serialise");
        let recovered: MempoolEnvelope = bcs::from_bytes(&bytes).expect("deserialise");
        assert_eq!(envelope, recovered);
    }

    #[test]
    fn mempool_envelope_regime_dispatch() {
        let tl = MempoolEnvelope::TimeLock(fixture_time_lock_envelope());
        let th = MempoolEnvelope::Threshold(fixture_threshold_envelope());
        assert_eq!(tl.regime(), Regime::TimeLock);
        assert_eq!(th.regime(), Regime::Threshold);
    }
}
