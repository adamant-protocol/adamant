#![allow(clippy::doc_markdown, clippy::doc_lazy_continuation)]
//! Adamant `FixedPoints` impl for the value-commitment ECC
//! chip per whitepaper §7.3.1.2.
//!
//! Phase 6.8b.4d-2.c.1. Provides the [`AdamantFixedPoints`]
//! type implementing `adamant_halo2::ecc::FixedPoints<pallas::Affine>`
//! with the §7.3.1.2 universal randomness generator `R` as the
//! sole `FullScalar` fixed point. This unlocks
//! `mul_fixed::full_width(r, R)` for the Pedersen-commitment
//! `r · R` term — the path needed because upstream
//! `EccChip::mul` for `FullWidth` variable-base scalars is
//! `todo!()` in `halo2_gadgets 0.3.1`.
//!
//! # Why fixed-base for R + variable-base for V_τ?
//!
//! `R` is a single Pallas point fixed across the protocol
//! (per §7.3.1.2, derived from
//! `b"ADAMANT-v1-vc-randomness"`). Fixed-base scalar mul
//! produces a working `r · R` for any Pallas scalar `r ∈ Fq`
//! using precomputed Lagrange tables.
//!
//! `V_τ` is asset-specific — different per asset type — so
//! it cannot be fixed at circuit-construction time. We use
//! variable-base scalar mul with `v` as a base-field element
//! (`v` is a u64 ⊂ Pallas base field), which works because
//! upstream's `mul::Config::assign` for `BaseFieldElem`
//! variant IS implemented. `V_τ` is witnessed as a
//! [`NonIdentityEccPoint`] supplied by the caller; the
//! chain-level binding from `V_τ` to `asset_type` is enforced
//! off-circuit via [`crate::value_commitment::asset_value_generator`]
//! consistency at validation time. (In-circuit
//! hash-to-curve for full asset-type privacy is a future
//! sub-arc requiring a Pallas hash-to-curve gadget.)
//!
//! # Lagrange-coefficient generation
//!
//! Phase 6.8b.4d-2.c.1 computes the per-window `(z, u)`
//! values for `R` at first use via the upstream
//! `find_zs_and_us(R, NUM_WINDOWS)` helper, cached in a
//! `lazy_static`. This is functionally identical to Zcash
//! Orchard's hardcoded constants but defers the offline
//! tooling step. Phase 6.8b.4d-2.c.2 (or pre-mainnet
//! hardening) replaces the runtime computation with
//! hardcoded `pub static` arrays plus a `test_zs_and_us`
//! verification test pinning byte-identity to the runtime
//! computation.
//!
//! # Stub roles for `ShortScalar` and `Base`
//!
//! `EccChip`'s `FixedPoints` trait requires three associated
//! types (`FullScalar`, `ShortScalar`, `Base`). Adamant uses
//! only `FullScalar` (`R` for `r · R`). The `ShortScalar` and
//! `Base` slots are filled with stub types that wrap the same
//! `R` generator — they implement the trait but are never
//! invoked at runtime. The stubs allow `EccChip::configure`
//! to compile against `AdamantFixedPoints`; calling
//! `mul_fixed_short` or `mul_fixed_base` against them would
//! be a logic bug (Adamant has no use site).

use std::sync::OnceLock;

use adamant_crypto::domain;
use adamant_halo2::ecc::chip::constants::{find_zs_and_us, H, NUM_WINDOWS, NUM_WINDOWS_SHORT};
use adamant_halo2::ecc::chip::{BaseFieldElem, FixedPoint, FullScalar, ShortScalar};
use adamant_halo2::ecc::FixedPoints;
use pasta_curves::arithmetic::CurveExt;
use pasta_curves::group::ff::PrimeField;
use pasta_curves::group::Curve;
use pasta_curves::pallas;

/// Adamant's `FixedPoints` impl for the value-commitment
/// ECC chip. The single load-bearing role is `FullScalar = R`,
/// the §7.3.1.2 universal randomness generator. `ShortScalar`
/// and `Base` are stubs (Adamant does not invoke `mul_fixed`
/// in those modes for value commitments).
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct AdamantFixedPoints;

impl FixedPoints<pallas::Affine> for AdamantFixedPoints {
    type FullScalar = RFullScalar;
    type ShortScalar = RShortScalar;
    type Base = RBaseField;
}

/// The §7.3.1.2 universal randomness generator `R` derived
/// via Pallas hash-to-curve under the
/// `adamant_crypto::domain::VALUE_COMMITMENT_RANDOMNESS`
/// domain tag.
///
/// Cached after first call. Identical to
/// [`crate::value_commitment::randomness_generator`]'s output
/// — both compute `R = HashToCurve("ADAMANT-v1-vc-randomness", b"")`.
fn r_generator_affine() -> pallas::Affine {
    static R: OnceLock<pallas::Affine> = OnceLock::new();
    *R.get_or_init(|| {
        let domain_str = core::str::from_utf8(domain::VALUE_COMMITMENT_RANDOMNESS.as_bytes())
            .expect("VALUE_COMMITMENT_RANDOMNESS tag is ASCII");
        let hasher = pallas::Point::hash_to_curve(domain_str);
        hasher(b"").to_affine()
    })
}

/// Per-window `(z, u)` values for `R` at `NUM_WINDOWS = 85`
/// (full Pallas-scalar bit width, 3-bit windows). Computed
/// once at first use via `find_zs_and_us`. Phase 6.8b.4d-2.c.2
/// will replace this with hardcoded constants + a parity test.
fn r_zs_and_us_full() -> &'static Vec<(u64, [pallas::Base; H])> {
    static ZS_AND_US: OnceLock<Vec<(u64, [pallas::Base; H])>> = OnceLock::new();
    ZS_AND_US.get_or_init(|| {
        find_zs_and_us(r_generator_affine(), NUM_WINDOWS)
            .expect("find_zs_and_us must succeed for the registered R generator at NUM_WINDOWS")
    })
}

/// Per-window `(z, u)` values for `R` at `NUM_WINDOWS_SHORT`
/// (64-bit signed scalar). Stub support for the
/// [`RShortScalar`] never-invoked code path.
fn r_zs_and_us_short() -> &'static Vec<(u64, [pallas::Base; H])> {
    static ZS_AND_US: OnceLock<Vec<(u64, [pallas::Base; H])>> = OnceLock::new();
    ZS_AND_US.get_or_init(|| {
        find_zs_and_us(r_generator_affine(), NUM_WINDOWS_SHORT)
            .expect("find_zs_and_us must succeed at NUM_WINDOWS_SHORT")
    })
}

/// FullScalar fixed-base `R` generator — the load-bearing
/// fixed point used by [`crate::circuit::ValueCommitmentCircuit`]
/// for the `r · R` term of the §7.3.1.2 Pedersen commitment.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RFullScalar;

impl FixedPoint<pallas::Affine> for RFullScalar {
    type FixedScalarKind = FullScalar;

    fn generator(&self) -> pallas::Affine {
        r_generator_affine()
    }

    fn u(&self) -> Vec<[<pallas::Base as PrimeField>::Repr; H]> {
        r_zs_and_us_full()
            .iter()
            .map(|(_, us)| {
                let mut out = [<pallas::Base as PrimeField>::Repr::default(); H];
                for (slot, u) in out.iter_mut().zip(us.iter()) {
                    *slot = u.to_repr();
                }
                out
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        r_zs_and_us_full().iter().map(|(z, _)| *z).collect()
    }
}

/// `ShortScalar` stub. Never invoked by Adamant's value-
/// commitment circuit — exists solely to satisfy the
/// [`FixedPoints`] trait's three-associated-type contract.
/// Reuses the same `R` generator so the table generation
/// reuses one cache.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RShortScalar;

impl FixedPoint<pallas::Affine> for RShortScalar {
    type FixedScalarKind = ShortScalar;

    fn generator(&self) -> pallas::Affine {
        r_generator_affine()
    }

    fn u(&self) -> Vec<[<pallas::Base as PrimeField>::Repr; H]> {
        r_zs_and_us_short()
            .iter()
            .map(|(_, us)| {
                let mut out = [<pallas::Base as PrimeField>::Repr::default(); H];
                for (slot, u) in out.iter_mut().zip(us.iter()) {
                    *slot = u.to_repr();
                }
                out
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        r_zs_and_us_short().iter().map(|(z, _)| *z).collect()
    }
}

/// `Base` (base-field-element scalar) stub. Same role as
/// [`RShortScalar`] — never invoked, exists for trait-
/// completion. Uses the FullScalar window count.
#[derive(Debug, Eq, PartialEq, Clone)]
pub struct RBaseField;

impl FixedPoint<pallas::Affine> for RBaseField {
    type FixedScalarKind = BaseFieldElem;

    fn generator(&self) -> pallas::Affine {
        r_generator_affine()
    }

    fn u(&self) -> Vec<[<pallas::Base as PrimeField>::Repr; H]> {
        r_zs_and_us_full()
            .iter()
            .map(|(_, us)| {
                let mut out = [<pallas::Base as PrimeField>::Repr::default(); H];
                for (slot, u) in out.iter_mut().zip(us.iter()) {
                    *slot = u.to_repr();
                }
                out
            })
            .collect()
    }

    fn z(&self) -> Vec<u64> {
        r_zs_and_us_full().iter().map(|(z, _)| *z).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::value_commitment::randomness_generator;

    /// `r_generator_affine()` matches the off-circuit
    /// [`crate::value_commitment::randomness_generator`] — both
    /// derive `R` from the same domain tag, so they MUST be
    /// the same Pallas point.
    #[test]
    fn r_in_circuit_matches_off_circuit() {
        let in_circuit = pallas::Point::from(r_generator_affine());
        let off_circuit = randomness_generator();
        assert_eq!(in_circuit, off_circuit);
    }

    /// `find_zs_and_us` produces NUM_WINDOWS entries for
    /// FullScalar. NB: triggers find_zs_and_us(R, 85) which
    /// is slow (~minutes) — `#[ignore]`-d until the
    /// pre-mainnet hardening sub-arc hardcodes the tables.
    #[test]
    #[ignore = "triggers find_zs_and_us(R, NUM_WINDOWS); slow"]
    fn r_full_scalar_zs_and_us_count() {
        let zs_and_us = r_zs_and_us_full();
        assert_eq!(zs_and_us.len(), NUM_WINDOWS);
    }

    /// FixedPoint::z() and FixedPoint::u() return matching-
    /// length vectors for FullScalar. NB: same reason as
    /// `r_full_scalar_zs_and_us_count` — triggers
    /// find_zs_and_us.
    #[test]
    #[ignore = "triggers find_zs_and_us(R, NUM_WINDOWS); slow"]
    fn r_full_scalar_zs_and_us_consistent_lengths() {
        let r = RFullScalar;
        let zs = r.z();
        let us = r.u();
        assert_eq!(zs.len(), NUM_WINDOWS);
        assert_eq!(us.len(), NUM_WINDOWS);
        for u_window in &us {
            assert_eq!(u_window.len(), H);
        }
    }

    /// Generators are equal across the three roles (we reuse
    /// R for all to minimise table generation).
    #[test]
    fn all_three_fixed_points_share_r() {
        let g_full = RFullScalar.generator();
        let g_short = RShortScalar.generator();
        let g_base = RBaseField.generator();
        assert_eq!(g_full, g_short);
        assert_eq!(g_full, g_base);
    }
}
