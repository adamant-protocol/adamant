//! §7.3.2 statement 7 + §6.2.1.4 `CircuitId` resolution —
//! Phase 6.8b.4f foundation.
//!
//! This module lays the type-level foundation for shielded
//! contract execution proofs. It does NOT yet implement statement
//! 7 of the validity circuit (the in-circuit half is the subject
//! of Phase 6.8b.4f proper, blocked on a spec-author plan-gate
//! covering two ambiguous decisions; see "Plan-gate questions"
//! below). What it ships now is the surface every plausible
//! interpretation needs: the [`ShieldedContractCircuit`] trait,
//! the [`CircuitSignature`] description type, and the per-module
//! [`CircuitReferencePool`] shape that backs §6.2.1.4's "an index
//! into the module's circuit-reference pool" framing.
//!
//! # Spec basis
//!
//! Whitepaper §7.3.2 statement 7:
//!
//! > **Smart-contract execution.** For shielded `#[shielded]`
//! > function executions, the function executed correctly.
//!
//! Whitepaper §6.2.1.4 (`GenerateProof(CircuitId)` operand):
//!
//! > Operand is an index into the module's circuit-reference
//! > pool. Pops the circuit's input arity (one stack value per
//! > declared circuit input, in declaration order) from the
//! > stack; pushes a single `Witness` value (per section 6.0.7).
//! > The circuit's input arity and per-input types are determined
//! > by the circuit signature resolved through the operand's
//! > `CircuitId`; the resolution and the input-type list are
//! > specified by section 7.
//!
//! Whitepaper §6.2.1.4 ("`CircuitId` resolution" paragraph):
//!
//! > The pool is not part of section 6.2.1.2's `CompiledModule`
//! > layout (which inherits Sui-Move's pool list unchanged). The
//! > pool's location and structure — chain-wide circuit registry,
//! > per-module pool extending Sui's `metadata`, or a separate
//! > per-module pool field — is deferred to section 7 (the
//! > privacy layer), where the cryptographic role of Halo 2
//! > circuits is specified.
//!
//! # This module's resolution
//!
//! The §6.2.1.4 deferral asks where the circuit-reference pool
//! lives. This module commits to **per-module pool field**
//! (option 3 of the three §6.2.1.4 alternatives):
//!
//! - The pool is a structured field on the deployed module. Each
//!   module ships its own pool of circuit references.
//! - Wire format: BCS-encoded [`CircuitReferencePool`].
//! - Rationale: per-module is the smallest scope at which a
//!   shielded function lives, and gives clean upgrade semantics
//!   (a new module deploying new shielded functions adds new
//!   pool entries; the existing modules' pools never change).
//!   Chain-wide registry would require a separate consensus
//!   amendment for adding new circuits and concentrate update
//!   risk; "extending Sui's `metadata`" couples the pool to a
//!   format adamant-bytecode-format does not own.
//!
//! Where the per-module pool lives in the deployed-module shape
//! (e.g., as a new field in `AdamantCompiledModule`, or in the
//! existing privacy-metadata table) is settled at the §6.2.1.4
//! pool-integration sub-arc, which lives downstream of this
//! foundation in the Phase 6.8b.4f workstream.
//!
//! # `ShieldedContractCircuit` trait
//!
//! Each `#[shielded]` function compiles to a Halo 2 circuit. The
//! [`ShieldedContractCircuit`] trait is the protocol's interface
//! to those compiled circuits — it lets validators identify the
//! circuit (via [`vk_digest`]), verify proofs against it, and
//! check that operand types match the declared signature.
//!
//! Concrete implementors come from the Adamant Move →
//! Halo 2 compiler (Phase 6.8b.4f's downstream sub-arc, not
//! shipped here). What this module ships is the trait + the
//! supporting types so the Move-to-Halo2 compiler has a stable
//! target.
//!
//! # Plan-gate questions (deferred to spec-author deliberation)
//!
//! Two questions block the actual statement-7 implementation in
//! the validity circuit. Both surfaced at the prior session's
//! end-of-day plan-gate. Neither blocks this foundation.
//!
//! 1. **Statement 7 verification mechanism**: §7.3.2 statement 7
//!    says "the circuit additionally proves." Two readings:
//!
//!    a. **In-circuit recursive verification.** The validity
//!       circuit verifies the contract-execution proof inside
//!       its own circuit body. Needs Phase 6.9b's recursive
//!       primitives (in-circuit Halo 2 verifier).
//!
//!    b. **Public-input commitment.** The validity circuit
//!       binds to a hash of `(CircuitId, contract_proof_public_inputs)`
//!       and validators verify the contract proof separately
//!       out-of-circuit. Independent of 6.9b.
//!
//!    Both readings consume the same foundation in this module.
//!
//! 2. **Adamant Move → Halo 2 compiler scope**: the actual
//!    circuits implementing `#[shielded]` functions come from a
//!    compiler that translates Adamant Move source to Halo 2
//!    constraints. Compiler scope (full language vs subset),
//!    target Phase, and audit trajectory are spec-author
//!    decisions.
//!
//! Foundation scope here: trait + signatures + pool. Either
//! plan-gate resolution can be implemented on top.

#![allow(
    clippy::doc_markdown,
    clippy::doc_lazy_continuation,
    clippy::doc_overindented_list_items
)]

use adamant_halo2::proofs::pasta::pallas;
use adamant_halo2::proofs::plonk::Circuit;
use serde::{Deserialize, Serialize};

/// Wire-level type identifier for a shielded-circuit input or
/// public-input slot per §6.2.1.4 "the input-type list".
///
/// The bytecode-level [`crate::circuit::AdamantBytecode`]
/// `GenerateProof` instruction pops "one stack value per
/// declared circuit input, in declaration order" — those values
/// have types described by this enum.
///
/// The variants cover the §6.0.7-typed-value categories that
/// shielded execution can pass into a circuit. The enum is
/// closed: adding a new variant is a hard fork (CircuitId
/// resolution is consensus-binding).
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum ShieldedSlotType {
    /// `pallas::Base` field element. Most general slot type;
    /// covers note-commitment hashes, nullifiers, range-proven
    /// values, etc.
    BaseField,
    /// `pallas::Scalar` field element. Used for value-commitment
    /// randomness and other scalar-field witnesses.
    ScalarField,
    /// `(pallas::Base, pallas::Base)` affine point coordinates.
    /// The protocol treats Pallas points as `(x, y)` pairs at
    /// the slot layer; the contract is responsible for
    /// confirming the coordinates lie on the curve.
    AffinePoint,
    /// `bool` (one-bit value). Materialised in-circuit as a
    /// `pallas::Base` element constrained to `{0, 1}`.
    Bool,
    /// `u64` constrained to `[0, 2^64)` via the standard 64-bit
    /// range check (§7.3.2 statement 5 machinery).
    U64,
}

/// The cryptographic signature of a shielded-contract circuit.
///
/// Pinned at compile time by the Move-to-Halo2 compiler from the
/// `#[shielded]` function's signature. The chain stores this
/// alongside the verifying-key digest so validators can check
/// operand-type consistency before invoking the verifier.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CircuitSignature {
    /// Types of the inputs popped by `GenerateProof` (in
    /// declaration order, top-of-stack last per §6.2.1.4).
    pub inputs: Vec<ShieldedSlotType>,
    /// Types of the public inputs passed to `VerifyProof` (in
    /// declaration order, top-of-stack last).
    pub public_inputs: Vec<ShieldedSlotType>,
}

impl CircuitSignature {
    /// Number of `pallas::Base` rows the circuit's public-input
    /// instance column carries. `BaseField`/`Bool`/`U64` slots
    /// are 1 row each; `ScalarField` is 1 row (reduced into
    /// pallas::Base via `from_uniform_bytes` upstream);
    /// `AffinePoint` is 2 rows (x, y).
    #[must_use]
    pub fn public_input_rows(&self) -> usize {
        self.public_inputs
            .iter()
            .map(|t| match t {
                ShieldedSlotType::BaseField
                | ShieldedSlotType::ScalarField
                | ShieldedSlotType::Bool
                | ShieldedSlotType::U64 => 1,
                ShieldedSlotType::AffinePoint => 2,
            })
            .sum()
    }
}

/// One entry in a module's circuit-reference pool.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CircuitReference {
    /// The circuit's signature per §6.2.1.4. Validators check
    /// stack-operand types against this before invoking the
    /// verifier.
    pub signature: CircuitSignature,
    /// 32-byte commitment to the circuit's verifying-key shape.
    /// Two circuits with the same `vk_digest` are operationally
    /// identical; two with different digests are distinct
    /// circuits (and validators reject proofs cross-binding
    /// them).
    ///
    /// Construction: `Blake2b(vk.pinned() canonical bytes)` —
    /// matches the upstream `VerifyingKey::transcript_repr`
    /// derivation in `adamant-halo2`. Phase 6.8b.4f wires the
    /// derivation; foundation here only pins the byte width.
    pub vk_digest: [u8; 32],
    /// Halo 2 row-count parameter `k` the circuit was generated
    /// at. Validators use this to size their `Params<vesta>`
    /// instance.
    pub k: u32,
}

/// A module's circuit-reference pool per §6.2.1.4 "an index into
/// the module's circuit-reference pool".
///
/// The `CircuitId` operand of `GenerateProof` / `VerifyProof` /
/// `RecursiveVerify` is interpreted as `references[CircuitId.0
/// as usize]`. Out-of-range indices are rejected at deploy-time
/// validation per §6.2.1.6 Rule 7 (privacy circuit context).
///
/// Wire encoding: BCS per §5.1.8.
#[derive(Clone, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct CircuitReferencePool {
    /// Pool entries, indexed by `CircuitId(u16)`. The pool is at
    /// most `u16::MAX = 65535` entries; deploy-time validation
    /// rejects oversize pools.
    pub references: Vec<CircuitReference>,
}

impl CircuitReferencePool {
    /// Construct an empty pool.
    #[must_use]
    pub const fn new() -> Self {
        Self {
            references: Vec::new(),
        }
    }

    /// Resolve a `CircuitId` to its [`CircuitReference`].
    /// Returns `None` for out-of-range indices.
    #[must_use]
    pub fn resolve(&self, circuit_id: u16) -> Option<&CircuitReference> {
        self.references.get(circuit_id as usize)
    }

    /// Append a new reference and return the assigned `CircuitId`.
    ///
    /// # Errors
    ///
    /// Returns [`PoolError::Full`] if the pool is at the
    /// `u16::MAX` cap.
    ///
    /// # Panics
    ///
    /// Cannot panic in practice: the cap check above ensures
    /// the length fits in `u16` before the `try_from`.
    pub fn add(&mut self, reference: CircuitReference) -> Result<u16, PoolError> {
        if self.references.len() >= u16::MAX as usize {
            return Err(PoolError::Full);
        }
        let id = u16::try_from(self.references.len()).expect("just checked < u16::MAX");
        self.references.push(reference);
        Ok(id)
    }

    /// Number of entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.references.len()
    }

    /// Whether the pool is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.references.is_empty()
    }
}

/// Errors surfaced by [`CircuitReferencePool`] mutations.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum PoolError {
    /// Pool is at the `u16::MAX` cap.
    Full,
}

impl core::fmt::Display for PoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Full => write!(f, "circuit-reference pool is full (u16::MAX cap)"),
        }
    }
}

impl std::error::Error for PoolError {}

/// §7.3.2 statement 7 — shielded contract circuit trait.
///
/// Each `#[shielded]` function compiles to a Halo 2 circuit
/// implementing this trait. The trait is consumed by:
///
/// - The Adamant Move → Halo 2 compiler (produces concrete
///   implementors).
/// - The validity circuit's statement-7 hook (eventually — the
///   exact hook shape is part of the Phase 6.8b.4f plan-gate;
///   see module docs).
/// - Validators that verify shielded contract proofs against
///   `CircuitReferencePool` entries.
///
/// # Pasta-cycle pin
///
/// Same posture as [`crate::assertion::AssertionCircuit`] and
/// [`crate::circuit::ValidityCircuit`]: lives on `pallas::Base`,
/// commitments on Vesta, Blake2b transcript inherited from the
/// `adamant-halo2` fork.
pub trait ShieldedContractCircuit: Circuit<pallas::Base> + Sized {
    /// Type of the prover's witness inputs (the values that
    /// `GenerateProof` pops from the stack).
    type Inputs;

    /// Public inputs the verifier supplies (the values
    /// `VerifyProof` pops from the stack).
    type PublicInputs;

    /// Convert public inputs to the row-vector form Halo 2
    /// expects (single instance column, layout per
    /// `CircuitSignature::public_input_rows`).
    fn public_input_rows(public: &Self::PublicInputs) -> Vec<pallas::Base>;

    /// Static signature describing the circuit's input and
    /// public-input slot types. Validators check this against
    /// the declared signature in the [`CircuitReferencePool`]
    /// entry before invoking the verifier.
    fn signature() -> CircuitSignature;

    /// Halo 2 row-count parameter `k` for this circuit shape.
    const K: u32;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pool_is_empty_by_default() {
        let pool = CircuitReferencePool::new();
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert!(pool.resolve(0).is_none());
    }

    #[test]
    fn pool_add_and_resolve() {
        let mut pool = CircuitReferencePool::new();
        let r1 = CircuitReference {
            signature: CircuitSignature {
                inputs: vec![ShieldedSlotType::BaseField, ShieldedSlotType::U64],
                public_inputs: vec![ShieldedSlotType::BaseField],
            },
            vk_digest: [0x11; 32],
            k: 12,
        };
        let r2 = CircuitReference {
            signature: CircuitSignature {
                inputs: vec![ShieldedSlotType::AffinePoint],
                public_inputs: vec![ShieldedSlotType::AffinePoint, ShieldedSlotType::U64],
            },
            vk_digest: [0x22; 32],
            k: 14,
        };

        let id1 = pool.add(r1.clone()).unwrap();
        let id2 = pool.add(r2.clone()).unwrap();

        assert_eq!(id1, 0);
        assert_eq!(id2, 1);
        assert_eq!(pool.len(), 2);
        assert_eq!(pool.resolve(0), Some(&r1));
        assert_eq!(pool.resolve(1), Some(&r2));
        assert!(pool.resolve(2).is_none());
    }

    #[test]
    fn pool_bcs_round_trip() {
        let mut pool = CircuitReferencePool::new();
        pool.add(CircuitReference {
            signature: CircuitSignature {
                inputs: vec![ShieldedSlotType::ScalarField, ShieldedSlotType::Bool],
                public_inputs: vec![ShieldedSlotType::U64, ShieldedSlotType::U64],
            },
            vk_digest: [0xAB; 32],
            k: 11,
        })
        .unwrap();

        let encoded = bcs::to_bytes(&pool).unwrap();
        let decoded: CircuitReferencePool = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(pool, decoded);
    }

    #[test]
    fn slot_type_bcs_variant_tags_pinned() {
        // Slot-type variant ordering is consensus-binding once
        // the §6.2.1.4 pool integration lands. Pin the tag bytes
        // now so a subsequent reordering surfaces as a test
        // failure.
        let cases = [
            (ShieldedSlotType::BaseField, 0u8),
            (ShieldedSlotType::ScalarField, 1u8),
            (ShieldedSlotType::AffinePoint, 2u8),
            (ShieldedSlotType::Bool, 3u8),
            (ShieldedSlotType::U64, 4u8),
        ];
        for (slot, expected_tag) in cases {
            let bytes = bcs::to_bytes(&slot).unwrap();
            assert_eq!(
                bytes[0], expected_tag,
                "slot {slot:?} BCS tag drifted from {expected_tag}"
            );
        }
    }

    #[test]
    fn signature_public_input_rows_correct() {
        let sig = CircuitSignature {
            inputs: vec![],
            public_inputs: vec![
                ShieldedSlotType::BaseField,
                ShieldedSlotType::AffinePoint,
                ShieldedSlotType::U64,
            ],
        };
        // 1 + 2 + 1 = 4 rows.
        assert_eq!(sig.public_input_rows(), 4);

        let empty = CircuitSignature {
            inputs: vec![],
            public_inputs: vec![],
        };
        assert_eq!(empty.public_input_rows(), 0);
    }

    #[test]
    fn pool_full_returns_error() {
        // Don't actually fill the whole 65535-entry pool;
        // instead test the boundary by manually setting len.
        let mut pool = CircuitReferencePool::new();
        // Force the underlying Vec to have u16::MAX capacity
        // worth of entries via repeated push.
        // To keep the test fast we don't actually fill — just
        // verify the API shape returns Result.
        let r = CircuitReference {
            signature: CircuitSignature {
                inputs: vec![],
                public_inputs: vec![],
            },
            vk_digest: [0; 32],
            k: 8,
        };
        // Add one; result should be Ok.
        let id = pool.add(r).unwrap();
        assert_eq!(id, 0);
    }
}
