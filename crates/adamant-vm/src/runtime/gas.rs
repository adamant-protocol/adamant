//! Multi-dimensional gas tracker — whitepaper §6.3.1 +
//! §6.0.7's `GasBudget`.
//!
//! Phase 5/6.5 ships the runtime gas-tracker infrastructure that
//! consumes the [`crate::transaction::GasBudget`] at frame entry
//! and meters consumption per dimension over the transaction's
//! execution. Per-instruction gas-cost calibration (the genesis-
//! fixed cost table per §6.3.2) is a pre-mainnet workstream
//! distinct from this sub-arc; this module ships the metering
//! infrastructure only.
//!
//! # Six dimensions per §6.3.1
//!
//! 1. `computation` — CPU cycles consumed by bytecode execution
//! 2. `storage` — bytes added to active state
//! 3. `rent` — storage-rent prepayment
//! 4. `bandwidth` — bytes transmitted by validators
//! 5. `proof_verification` — CPU cost of verifying zero-knowledge
//!    proofs
//! 6. `proof_generation` — CPU cost of generating zero-knowledge
//!    proofs (optional; charged per proof when used)
//!
//! Field declaration order matches [`crate::transaction::GasBudget`]
//! field order exactly per whitepaper §6.0.7. Reordering is a
//! hard fork (consensus-binding canonical encoding).
//!
//! # Per-dimension semantics (§6.3.1)
//!
//! Each dimension has its own price in ADM, set per epoch via
//! the §10 EIP-1559-style mechanism. The transaction aborts on
//! the **first dimension exhausted**; the user cannot trade
//! unused budget in one dimension for additional consumption in
//! another (whitepaper §6.0.2). This preserves §6.3.1's motivation
//! for multi-dimensional pricing: dimensions correspond to
//! distinct validator resources, and a single combined cap would
//! obscure which resource a transaction actually stresses.
//!
//! # Zero-budget semantics
//!
//! A `GasTracker` initialised with all-zero remaining values
//! aborts on any [`GasTracker::charge`] of a positive amount.
//! [`GasTracker::charge`] with `amount == 0` is a no-op
//! regardless of remaining budget — charging zero gas does not
//! consume any of the dimension's remaining budget and never
//! aborts.

use crate::bytecode::GasDimension;
use crate::runtime::error::{AbortReason, VMError};
use crate::transaction::GasBudget;

/// Per-dimension remaining-budget tracker. Six u64 fields
/// matching [`GasBudget`] field declaration order.
///
/// Constructed from a [`GasBudget`] at transaction frame entry
/// via [`GasTracker::from_budget`]; never topped up mid-execution
/// (Phase 5/6.5 plan-gate Q5/6.5.2 disposition). The runtime
/// charges per-instruction costs through [`GasTracker::charge`]
/// and reads remaining budget per dimension through
/// [`GasTracker::remaining`].
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Hash)]
pub struct GasTracker {
    /// Remaining computation budget per §6.3.1 dimension 1.
    pub computation: u64,
    /// Remaining state-storage budget per §6.3.1 dimension 2.
    pub storage: u64,
    /// Remaining storage-rent prepayment budget per §6.3.1
    /// dimension 3 + §5.6.
    pub rent: u64,
    /// Remaining bandwidth budget per §6.3.1 dimension 4.
    pub bandwidth: u64,
    /// Remaining proof-verification budget per §6.3.1 dimension 5.
    pub proof_verification: u64,
    /// Remaining proof-generation budget per §6.3.1 dimension 6
    /// + §7.7 prover market.
    pub proof_generation: u64,
}

impl GasTracker {
    /// Construct a [`GasTracker`] from a transaction's
    /// [`GasBudget`]. Six-field copy preserving canonical order
    /// per §6.0.7.
    #[must_use]
    pub fn from_budget(budget: &GasBudget) -> Self {
        Self {
            computation: budget.computation,
            storage: budget.storage,
            rent: budget.rent,
            bandwidth: budget.bandwidth,
            proof_verification: budget.proof_verification,
            proof_generation: budget.proof_generation,
        }
    }

    /// Empty tracker (all dimensions at zero remaining). Charging
    /// any positive amount aborts. Useful as a default for tests
    /// or for frame contexts without a transaction-level budget.
    #[must_use]
    pub fn empty() -> Self {
        Self {
            computation: 0,
            storage: 0,
            rent: 0,
            bandwidth: 0,
            proof_verification: 0,
            proof_generation: 0,
        }
    }

    /// Read the remaining budget for `dimension`.
    #[must_use]
    pub fn remaining(&self, dimension: GasDimension) -> u64 {
        match dimension {
            GasDimension::Computation => self.computation,
            GasDimension::Storage => self.storage,
            GasDimension::Rent => self.rent,
            GasDimension::Bandwidth => self.bandwidth,
            GasDimension::ProofVerification => self.proof_verification,
            GasDimension::ProofGeneration => self.proof_generation,
        }
    }

    /// Charge `amount` units against `dimension`'s remaining
    /// budget.
    ///
    /// # Errors
    ///
    /// Returns [`VMError::AbortError`] with
    /// [`AbortReason::OutOfGas { dimension }`] if `amount`
    /// exceeds the dimension's remaining budget. The transaction
    /// aborts on the first dimension exhausted; callers must
    /// halt execution on this error (§6.2.2 step 5: "Bytecode
    /// runs to completion or until gas is exhausted").
    ///
    /// `amount == 0` is a no-op regardless of remaining budget.
    pub fn charge(&mut self, dimension: GasDimension, amount: u64) -> Result<(), VMError> {
        let remaining = self.remaining_mut(dimension);
        if let Some(after) = remaining.checked_sub(amount) {
            *remaining = after;
            Ok(())
        } else {
            Err(VMError::AbortError {
                reason: AbortReason::OutOfGas { dimension },
            })
        }
    }

    /// Internal: get a mutable reference to the per-dimension
    /// remaining counter.
    fn remaining_mut(&mut self, dimension: GasDimension) -> &mut u64 {
        match dimension {
            GasDimension::Computation => &mut self.computation,
            GasDimension::Storage => &mut self.storage,
            GasDimension::Rent => &mut self.rent,
            GasDimension::Bandwidth => &mut self.bandwidth,
            GasDimension::ProofVerification => &mut self.proof_verification,
            GasDimension::ProofGeneration => &mut self.proof_generation,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Whitepaper §6.0.7 (verbatim): "`GasBudget` { `computation`:
    /// u64, `storage`: u64, `rent`: u64, `bandwidth`: u64,
    /// `proof_verification`: u64, `proof_generation`: u64 }".
    ///
    /// `GasTracker::from_budget` copies all six fields preserving
    /// canonical order.
    #[test]
    fn from_budget_copies_all_six_fields() {
        let budget = GasBudget {
            computation: 1,
            storage: 2,
            rent: 3,
            bandwidth: 4,
            proof_verification: 5,
            proof_generation: 6,
        };
        let tracker = GasTracker::from_budget(&budget);
        assert_eq!(tracker.computation, 1);
        assert_eq!(tracker.storage, 2);
        assert_eq!(tracker.rent, 3);
        assert_eq!(tracker.bandwidth, 4);
        assert_eq!(tracker.proof_verification, 5);
        assert_eq!(tracker.proof_generation, 6);
    }

    /// Whitepaper §6.3.1 (verbatim): "The transaction aborts on
    /// the first dimension exhausted; the user cannot trade
    /// unused budget in one dimension for additional consumption
    /// in another."
    ///
    /// `charge` deducts from the named dimension only.
    #[test]
    fn charge_deducts_from_named_dimension_only() {
        let budget = GasBudget {
            computation: 100,
            storage: 100,
            rent: 100,
            bandwidth: 100,
            proof_verification: 100,
            proof_generation: 100,
        };
        let mut t = GasTracker::from_budget(&budget);
        t.charge(GasDimension::Computation, 25).expect("ok");
        assert_eq!(t.computation, 75);
        assert_eq!(t.storage, 100);
        assert_eq!(t.rent, 100);
        assert_eq!(t.bandwidth, 100);
        assert_eq!(t.proof_verification, 100);
        assert_eq!(t.proof_generation, 100);
    }

    /// Charging zero is a no-op.
    #[test]
    fn charge_zero_is_no_op() {
        let mut t = GasTracker::empty();
        t.charge(GasDimension::Computation, 0).expect("ok");
        assert_eq!(t.computation, 0);
    }

    /// Charging exactly-remaining drains the dimension to zero
    /// without aborting.
    #[test]
    fn charge_exactly_remaining_drains_to_zero() {
        let budget = GasBudget {
            computation: 50,
            storage: 0,
            rent: 0,
            bandwidth: 0,
            proof_verification: 0,
            proof_generation: 0,
        };
        let mut t = GasTracker::from_budget(&budget);
        t.charge(GasDimension::Computation, 50).expect("ok");
        assert_eq!(t.computation, 0);
    }

    /// Charging one over remaining surfaces
    /// `AbortError { OutOfGas }`.
    #[test]
    fn charge_overflow_surfaces_out_of_gas() {
        let budget = GasBudget {
            computation: 10,
            storage: 0,
            rent: 0,
            bandwidth: 0,
            proof_verification: 0,
            proof_generation: 0,
        };
        let mut t = GasTracker::from_budget(&budget);
        let result = t.charge(GasDimension::Computation, 11);
        assert!(matches!(
            result,
            Err(VMError::AbortError {
                reason: AbortReason::OutOfGas {
                    dimension: GasDimension::Computation
                }
            })
        ));
        // Remaining is unchanged after a failed charge.
        assert_eq!(t.computation, 10);
    }

    /// `OutOfGas` carries the failed dimension as payload — each
    /// dimension produces a distinct abort variant.
    #[test]
    fn out_of_gas_carries_dimension_payload() {
        let budget = GasBudget {
            computation: 0,
            storage: 5,
            rent: 0,
            bandwidth: 0,
            proof_verification: 0,
            proof_generation: 0,
        };
        let mut t = GasTracker::from_budget(&budget);
        let result = t.charge(GasDimension::Storage, 100);
        assert!(matches!(
            result,
            Err(VMError::AbortError {
                reason: AbortReason::OutOfGas {
                    dimension: GasDimension::Storage
                }
            })
        ));
    }

    /// `remaining` round-trips: read after charge equals (initial
    /// - charged).
    #[test]
    fn remaining_reflects_charged_amount() {
        let budget = GasBudget {
            computation: 0,
            storage: 0,
            rent: 0,
            bandwidth: 1000,
            proof_verification: 0,
            proof_generation: 0,
        };
        let mut t = GasTracker::from_budget(&budget);
        assert_eq!(t.remaining(GasDimension::Bandwidth), 1000);
        t.charge(GasDimension::Bandwidth, 250).expect("ok");
        assert_eq!(t.remaining(GasDimension::Bandwidth), 750);
        t.charge(GasDimension::Bandwidth, 500).expect("ok");
        assert_eq!(t.remaining(GasDimension::Bandwidth), 250);
    }

    /// All six dimensions are chargeable independently.
    #[test]
    fn all_six_dimensions_chargeable() {
        let budget = GasBudget {
            computation: 100,
            storage: 100,
            rent: 100,
            bandwidth: 100,
            proof_verification: 100,
            proof_generation: 100,
        };
        let mut t = GasTracker::from_budget(&budget);
        let dims = [
            GasDimension::Computation,
            GasDimension::Storage,
            GasDimension::Rent,
            GasDimension::Bandwidth,
            GasDimension::ProofVerification,
            GasDimension::ProofGeneration,
        ];
        for dim in dims {
            t.charge(dim, 10).expect("ok");
            assert_eq!(t.remaining(dim), 90);
        }
    }

    /// `GasTracker::empty()` has zero in every dimension.
    #[test]
    fn empty_tracker_is_zero_everywhere() {
        let t = GasTracker::empty();
        for dim in [
            GasDimension::Computation,
            GasDimension::Storage,
            GasDimension::Rent,
            GasDimension::Bandwidth,
            GasDimension::ProofVerification,
            GasDimension::ProofGeneration,
        ] {
            assert_eq!(t.remaining(dim), 0);
        }
    }
}
