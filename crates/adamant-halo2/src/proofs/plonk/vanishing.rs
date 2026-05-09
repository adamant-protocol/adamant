use std::marker::PhantomData;

use crate::proofs::arithmetic::CurveAffine;

mod prover;
mod verifier;

/// A vanishing argument.
pub(crate) struct Argument<C: CurveAffine> {
    _marker: PhantomData<C>,
}
