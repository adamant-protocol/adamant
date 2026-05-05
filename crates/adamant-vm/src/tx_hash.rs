//! `TxHash` derivation per whitepaper section 6.0.4.
//!
//! Per whitepaper section 6.0.4:
//!
//! > "The transaction hash is computed over the canonical BCS
//! > encoding of the body alone:
//! >
//! > ```text
//! > TxHash = sha3_256_tagged(TX_HASH, BCS(body))
//! > ```
//! >
//! > where `TX_HASH` is the registered domain tag
//! > `b"ADAMANT-v1-tx-hash"` per section 3.3.1, and `BCS(body)` is
//! > the canonical encoding per section 5.1.8."
//!
//! This module mirrors the shape of `adamant-account::derive_address`
//! (whitepaper section 4.2) and `adamant-state::derive_object_id`
//! (whitepaper section 5.1.1): a single derivation function plus
//! BCS-canonicality and known-answer regression tests pinning the
//! consensus-critical wire format. See CONTRIBUTING.md "Derivation
//! discipline" for the four invariants.

use adamant_crypto::{domain, hash::sha3_256_tagged};
use adamant_types::TxHash;

use crate::transaction::TxBody;

/// Derive the [`TxHash`] of a transaction body per whitepaper
/// section 6.0.4.
///
/// `TxHash = sha3_256_tagged(TX_HASH, BCS(body))`
///
/// The hash covers the body alone (per whitepaper section 6.0.1's
/// body / auth-evidence split); auth evidence is excluded so
/// signatures can sign `BCS(body)` without circular dependency.
/// Two transactions with byte-identical bodies but different auth
/// evidence have the same `TxHash` — that is intentional per
/// whitepaper section 6.0.1 ("the `TxHash` identifies the operation
/// a user committed to, not the particular signature instance
/// carrying it").
///
/// # Determinism
///
/// Identical inputs always produce identical output. Required by
/// consensus — every validator must derive the same `TxHash` for
/// the same body bytes.
///
/// # Panics
///
/// Cannot panic in practice. The internal `expect` is a contract
/// assertion: BCS encoding of [`TxBody`] is well-defined for every
/// canonical input shape per whitepaper section 6.0.7, and
/// `bcs::to_bytes` does not fail for inputs that uphold that
/// contract. A panic would indicate a defect in BCS or in this
/// crate's `Serialize` derive on transaction sub-types, not a
/// runtime failure mode.
#[must_use]
pub fn derive_tx_hash(body: &TxBody) -> TxHash {
    let bcs_bytes = bcs::to_bytes(body).expect(
        "TxBody is a fixed-shape struct of BCS-canonical fields per whitepaper §6.0.2 \
         and §6.0.7; BCS encoding never fails for inputs of this shape — if this trips, \
         the spec was changed without updating the type",
    );
    let hash = sha3_256_tagged(&domain::TX_HASH, &bcs_bytes);
    TxHash::from_bytes(hash)
}

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_types::{Address, FunctionId, ModuleRef, Mutability, ObjectId, Ownership, TypeId};
    use hex_literal::hex;

    use crate::transaction::{AccountRef, CallParams, CreatedObject, GasBudget, TxBody};
    use crate::value::Value;

    fn fixed_address(b: u8) -> Address {
        Address::from_bytes([b; 32])
    }

    fn fixed_object_id(b: u8) -> ObjectId {
        ObjectId::from_bytes([b; 32])
    }

    fn fixed_type_id(b: u8) -> TypeId {
        TypeId::from_bytes([b; 32])
    }

    /// Construct the canonical KAT body — the same body used by
    /// `known_answer_regression_vector` and exercised by the
    /// `derivation_is_deterministic` and per-field distinctness
    /// tests so the same fixture is reused across the test set.
    ///
    /// Per the rich-KAT spec from the proposal: `Cleartext`
    /// `authorising_account`, `fee_payer` set, non-empty
    /// `read_set` (two version-pinned objects), `write_set` as a
    /// subset of `read_set`, one `created_object` with the
    /// authorising account as creator, `gas_budget` non-zero
    /// across multiple dimensions, `CallParams` targeting a
    /// real-looking module + function with a couple of `Value`
    /// arguments, non-zero `nonce`.
    fn kat_body() -> TxBody {
        TxBody {
            authorising_account: AccountRef::Cleartext(fixed_address(0x21)),
            fee_payer: Some(AccountRef::Cleartext(fixed_address(0x41))),
            read_set: vec![(fixed_object_id(0x61), 1), (fixed_object_id(0x81), 2)],
            write_set: vec![fixed_object_id(0x61)],
            created_objects: vec![CreatedObject {
                creator: fixed_address(0x21),
                creation_index: 0,
                type_id: fixed_type_id(0xa1),
                initial_owner: Ownership::Shared,
                initial_mutability: Mutability::Immutable,
            }],
            gas_budget: GasBudget {
                computation: 1_000_000,
                storage: 200,
                rent: 200,
                bandwidth: 5_000,
                proof_verification: 100,
                proof_generation: 100,
            },
            call: CallParams {
                target_module: ModuleRef(fixed_object_id(0xc1)),
                target_function: FunctionId::new("transfer".to_string()).expect("valid"),
                type_arguments: vec![],
                arguments: vec![Value::U64(42), Value::Address(fixed_address(0x21))],
            },
            nonce: 0x1234,
        }
    }

    /// Same body bytes → same [`TxHash`]. The protocol's minimum
    /// consensus requirement: every validator derives the same
    /// hash for the same body.
    #[test]
    fn derivation_is_deterministic() {
        let a = derive_tx_hash(&kat_body());
        let b = derive_tx_hash(&kat_body());
        assert_eq!(a, b);
    }

    /// Varying [`TxBody::nonce`] produces a different [`TxHash`].
    #[test]
    fn distinct_nonce_distinguishes() {
        let mut alt = kat_body();
        alt.nonce = 0x9999;
        assert_ne!(derive_tx_hash(&kat_body()), derive_tx_hash(&alt));
    }

    /// Varying [`TxBody::authorising_account`] produces a different
    /// [`TxHash`].
    #[test]
    fn distinct_authorising_account_distinguishes() {
        let mut alt = kat_body();
        alt.authorising_account = AccountRef::Cleartext(fixed_address(0xff));
        assert_ne!(derive_tx_hash(&kat_body()), derive_tx_hash(&alt));
    }

    /// Varying [`TxBody::fee_payer`] (Some/None or different
    /// address) produces a different [`TxHash`].
    #[test]
    fn distinct_fee_payer_distinguishes() {
        let mut alt = kat_body();
        alt.fee_payer = None;
        assert_ne!(derive_tx_hash(&kat_body()), derive_tx_hash(&alt));
    }

    /// Varying [`TxBody::read_set`] produces a different [`TxHash`].
    #[test]
    fn distinct_read_set_distinguishes() {
        let mut alt = kat_body();
        alt.read_set.push((fixed_object_id(0xff), 99));
        assert_ne!(derive_tx_hash(&kat_body()), derive_tx_hash(&alt));
    }

    /// Varying [`TxBody::write_set`] produces a different [`TxHash`].
    #[test]
    fn distinct_write_set_distinguishes() {
        let mut alt = kat_body();
        alt.write_set.clear();
        assert_ne!(derive_tx_hash(&kat_body()), derive_tx_hash(&alt));
    }

    /// Varying [`TxBody::created_objects`] produces a different
    /// [`TxHash`].
    #[test]
    fn distinct_created_objects_distinguishes() {
        let mut alt = kat_body();
        alt.created_objects.clear();
        assert_ne!(derive_tx_hash(&kat_body()), derive_tx_hash(&alt));
    }

    /// Varying [`TxBody::gas_budget`] produces a different
    /// [`TxHash`].
    #[test]
    fn distinct_gas_budget_distinguishes() {
        let mut alt = kat_body();
        alt.gas_budget.computation = alt.gas_budget.computation.wrapping_add(1);
        assert_ne!(derive_tx_hash(&kat_body()), derive_tx_hash(&alt));
    }

    /// Varying [`TxBody::call`] produces a different [`TxHash`].
    #[test]
    fn distinct_call_distinguishes() {
        let mut alt = kat_body();
        alt.call.target_function = FunctionId::new("noop".to_string()).expect("valid");
        assert_ne!(derive_tx_hash(&kat_body()), derive_tx_hash(&alt));
    }

    /// The domain tag is taken from the centralised registry, not
    /// inlined as a string literal. Pins the registry's byte
    /// string against whitepaper section 6.0.4. Tag changes are
    /// consensus rule changes per whitepaper 3.3.1.
    #[test]
    fn domain_tag_is_registry_value() {
        assert_eq!(domain::TX_HASH.as_bytes(), b"ADAMANT-v1-tx-hash");
    }

    /// Known-answer test pinning the canonical wire format for
    /// [`TxHash`] derivation under the rich KAT body fixture per
    /// CONTRIBUTING.md "Derivation discipline" rule 4: the
    /// regression test catches any future change that would
    /// produce a different `TxHash` from the same input.
    ///
    /// The expected bytes were generated by running this derivation
    /// once and committing the output. A different result from the
    /// same inputs indicates the `TxHash` wire format has drifted —
    /// which is a consensus rule change requiring whitepaper
    /// revision, not a test fix.
    #[test]
    fn known_answer_regression_vector() {
        let actual = derive_tx_hash(&kat_body());
        let expected = TxHash::from_bytes(hex!(
            "ef989367af03ef078bae88ced9fc1e2206e46c908a4c13e444f653e54ac2cdfa"
        ));
        assert_eq!(
            actual, expected,
            "tx-hash derivation regression — input/output stable wire format \
             for the rich KAT body. If this fails, the protocol's TxHash \
             wire format has drifted; investigate before changing the \
             expected bytes."
        );
    }
}
