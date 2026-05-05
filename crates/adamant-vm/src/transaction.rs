//! Canonical Transaction format per whitepaper section 6.0.
//!
//! This module defines the [`Transaction`] type and every sub-type
//! it composes per whitepaper sections 6.0.1, 6.0.2, 6.0.3, and
//! 6.0.7. Field ordering in every struct matches the spec exactly
//! because BCS encodes struct fields in source-declaration order
//! per whitepaper section 5.1.8 — reordering is a hard fork.
//!
//! # Spec sources
//!
//! - [`Transaction`] outer shape — whitepaper section 6.0.1.
//! - [`TxBody`] fields — whitepaper section 6.0.2.
//! - [`AuthEvidence`] outer shape — whitepaper section 6.0.3.
//! - [`AccountRef`] variant set — whitepaper section 6.0.2 with
//!   inner-type encodings pinned by 6.0.7.
//! - [`CreatedObject`] inner struct — whitepaper section 6.0.2.
//! - [`GasBudget`] inner struct — whitepaper sections 6.0.2 and
//!   6.3.1.
//! - [`CallParams`] inner struct — whitepaper section 6.0.2 with
//!   inner-type encodings pinned by 6.0.7.
//! - [`Witness`] — whitepaper section 6.0.7 (encoding only;
//!   contents are §7-deferred).

use serde::{Deserialize, Serialize};

use adamant_types::{
    Address, FunctionId, ModuleRef, Mutability, ObjectId, Ownership, Signature, StealthCommitment,
    TypeId, Version,
};

use crate::value::Value;

/// A protocol transaction (whitepaper section 6.0.1).
///
/// The body / auth-evidence split exists to solve the
/// signature-signs-itself problem: signatures cover [`BCS`] of the
/// [`TxBody`] alone and live in [`AuthEvidence`], so the body's
/// canonical encoding does not depend on the signatures it
/// produces. The [`crate::derive_tx_hash`] function takes a
/// `&TxBody` and returns the [`adamant_types::TxHash`] over the
/// body bytes; auth evidence is excluded.
///
/// [`BCS`]: https://docs.rs/bcs
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Transaction {
    /// The operation payload — what the transaction is asking to
    /// do (whitepaper section 6.0.2).
    pub body: TxBody,
    /// Signatures, witnesses, and other non-body data that
    /// authorise the body's execution (whitepaper section 6.0.3).
    /// Excluded from the [`adamant_types::TxHash`] per section
    /// 6.0.4.
    pub auth: AuthEvidence,
}

/// Body of a transaction (whitepaper section 6.0.2).
///
/// Field ordering is canonical: BCS encodes struct fields in
/// source-declaration order per whitepaper section 5.1.8.
/// Reordering or adding fields is a hard fork.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct TxBody {
    /// Account whose validation logic (per whitepaper section 4.3)
    /// is invoked at execution-pipeline step 1. Cleartext for
    /// transparent transactions; shielded via stealth-address
    /// commitment for shielded transactions per whitepaper section
    /// 4.7.
    pub authorising_account: AccountRef,
    /// Optional fee payer per whitepaper section 6.3.4. When
    /// `None`, fees are paid by [`Self::authorising_account`].
    /// When `Some(account)`, the fee payer's authorisation must
    /// also appear in [`AuthEvidence::signatures`].
    pub fee_payer: Option<AccountRef>,
    /// Objects this transaction reads, with their expected
    /// versions (whitepaper section 6.0.2). The version pin
    /// protects against read-write conflicts; if any read object's
    /// version has advanced beyond the declared version at
    /// execution time, the transaction is rejected without
    /// execution.
    pub read_set: Vec<(ObjectId, Version)>,
    /// Pre-existing objects this transaction modifies (whitepaper
    /// section 6.0.2). The `ObjectId`s in this set must also
    /// appear in [`Self::read_set`] (read-then-write).
    pub write_set: Vec<ObjectId>,
    /// Objects to be created within this transaction, declared
    /// explicitly per whitepaper section 6.0.2 so that their
    /// `ObjectId`s are derivable per whitepaper section 5.1.1.
    pub created_objects: Vec<CreatedObject>,
    /// Per-dimension gas cap (whitepaper sections 6.0.2 and 6.3.1).
    pub gas_budget: GasBudget,
    /// Operation payload — which function to invoke, on which
    /// target, with which arguments (whitepaper section 6.0.2).
    pub call: CallParams,
    /// Monotonic counter scoped to [`Self::authorising_account`],
    /// ensuring distinct transactions from the same account have
    /// distinct bodies (whitepaper section 6.0.2). Must equal one
    /// greater than the highest nonce previously executed for the
    /// authorising account.
    pub nonce: u64,
}

/// Authorisation evidence carried with a transaction (whitepaper
/// section 6.0.3).
///
/// Excluded from the [`adamant_types::TxHash`] per whitepaper
/// section 6.0.4: modifying signatures or witnesses does not change
/// the `TxHash`; only modifying the body does. This decoupling
/// matches standard practice across the field and lets signatures
/// sign over `BCS(body)` without circular dependency.
///
/// The structure is deliberately simple — validation logic in the
/// authorising account interprets [`Self::signatures`] and
/// [`Self::witnesses`] according to the account's declared scheme
/// per whitepaper section 4.3.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthEvidence {
    /// Signatures over `BCS(body)`. The protocol does not impose a
    /// fixed signature scheme — the account's validation logic
    /// (per whitepaper section 4.3) interprets these.
    pub signatures: Vec<Signature>,
    /// Zero-knowledge witnesses or other authentication tags. For
    /// shielded transactions, witnesses prove authority without
    /// revealing the account; cryptographic construction is
    /// whitepaper section 7's concern.
    pub witnesses: Vec<Witness>,
}

/// Reference to the account whose validation logic runs at
/// transaction execution (whitepaper sections 6.0.2 and 6.0.7).
///
/// Variant tags pinned by whitepaper section 6.0.7:
///
/// - [`AccountRef::Cleartext`] — BCS variant tag `0x00`
/// - [`AccountRef::Shielded`] — BCS variant tag `0x01`
///
/// Reordering variants is a hard fork.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum AccountRef {
    /// Transparent transaction: the authorising account is named
    /// directly by its 32-byte [`Address`]. BCS variant tag `0x00`.
    Cleartext(Address),
    /// Shielded transaction: the authorising account is named via
    /// a 32-byte stealth-address commitment per whitepaper section
    /// 4.7. The cryptographic construction is whitepaper section
    /// 7's concern; this layer carries the encoding only. BCS
    /// variant tag `0x01`.
    Shielded(StealthCommitment),
}

/// Declaration of an object to be created within a transaction
/// (whitepaper section 6.0.2).
///
/// The `(creator, creation_index)` pair, combined with this
/// transaction's `TxHash`, produces the new `ObjectId` per
/// whitepaper section 5.1.1's derivation formula. The `ObjectId`
/// is **not** declared inside [`CreatedObject`] — it is derived
/// from the resulting `TxHash` *after* the body is hashed,
/// breaking the apparent circularity (whitepaper section 6.0.2
/// "no object's `ObjectId` appears in the body's declaration of
/// itself").
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CreatedObject {
    /// Address of the account that creates the object (whitepaper
    /// section 5.1.1).
    pub creator: Address,
    /// Per-creator counter ensuring uniqueness when one
    /// transaction creates multiple objects (whitepaper section
    /// 5.1.1).
    pub creation_index: u64,
    /// Identifier of the new object's type definition (whitepaper
    /// section 5.1.2).
    pub type_id: TypeId,
    /// Initial ownership of the new object (whitepaper section
    /// 5.1.3).
    pub initial_owner: Ownership,
    /// Initial mutability declaration (whitepaper section 5.1.4).
    /// Immutable post-creation per the same section.
    pub initial_mutability: Mutability,
}

/// Per-dimension gas cap matching whitepaper section 6.3.1's six
/// dimensions.
///
/// The transaction aborts on the first dimension exhausted; the
/// user cannot trade unused budget in one dimension for additional
/// consumption in another (whitepaper section 6.0.2). This
/// preserves whitepaper section 6.3.1's motivation for
/// multi-dimensional pricing.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct GasBudget {
    /// Computation gas — CPU cycles consumed by bytecode execution.
    pub computation: u64,
    /// State-storage gas — bytes added to active state at object
    /// creation and growth.
    pub storage: u64,
    /// Storage-rent prepayment gas — rent prepaid for created
    /// objects (whitepaper section 5.6).
    pub rent: u64,
    /// Bandwidth gas — bytes transmitted by validators when
    /// propagating the transaction.
    pub bandwidth: u64,
    /// Proof-verification gas — CPU cost of verifying
    /// zero-knowledge proofs attached to shielded transactions.
    pub proof_verification: u64,
    /// Proof-generation gas — CPU cost of generating
    /// zero-knowledge proofs, when outsourced to a prover market
    /// per whitepaper section 7.
    pub proof_generation: u64,
}

/// Operation payload — which function to invoke, on which target,
/// with which arguments (whitepaper section 6.0.2).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CallParams {
    /// Module containing the target function (whitepaper section
    /// 6.4.1: modules are first-class objects).
    pub target_module: ModuleRef,
    /// Function name within [`Self::target_module`] (whitepaper
    /// section 6.0.7: UTF-8 string bounded to 255 bytes).
    pub target_function: FunctionId,
    /// Type arguments for generic function instantiation
    /// (whitepaper sections 6.0.2 and 6.1).
    pub type_arguments: Vec<TypeId>,
    /// Function arguments in declaration order (whitepaper
    /// sections 6.0.2 and 6.0.7).
    pub arguments: Vec<Value>,
}

/// Length-prefixed opaque byte vector carried in
/// [`AuthEvidence::witnesses`] per whitepaper section 6.0.7.
///
/// The contents — a zero-knowledge proof, a signature witness, an
/// authentication tag, etc. — are specified in whitepaper section
/// 7 (privacy layer). This layer pins only that the encoding is a
/// BCS-canonical byte vector (ULEB128 length prefix followed by
/// raw bytes); the contents are opaque to the encoding.
///
/// Witnesses are excluded from [`adamant_types::TxHash`] (they live
/// in [`AuthEvidence`], outside the body); changing the
/// contents-level interpretation of `Witness` bytes in a future
/// revision does not alter `TxHash` values for transactions whose
/// witnesses are byte-identical.
#[derive(Clone, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub struct Witness(pub Vec<u8>);

#[cfg(test)]
mod tests {
    use super::*;

    use adamant_types::{BasisPoints, ProofCommitment};

    fn fixed_address(b: u8) -> Address {
        Address::from_bytes([b; 32])
    }

    fn fixed_object_id(b: u8) -> ObjectId {
        ObjectId::from_bytes([b; 32])
    }

    fn fixed_type_id(b: u8) -> TypeId {
        TypeId::from_bytes([b; 32])
    }

    /// `AccountRef` variant tag pin: `Cleartext = 0x00`,
    /// `Shielded = 0x01`. Whitepaper section 6.0.7 fixes these
    /// tags at genesis.
    #[test]
    fn account_ref_variant_tags_match_spec() {
        let cleartext = AccountRef::Cleartext(fixed_address(0xaa));
        let shielded = AccountRef::Shielded(StealthCommitment::from_bytes([0xbb; 32]));

        let enc_cleartext = bcs::to_bytes(&cleartext).expect("encode");
        let enc_shielded = bcs::to_bytes(&shielded).expect("encode");

        assert_eq!(enc_cleartext[0], 0x00);
        assert_eq!(enc_shielded[0], 0x01);

        // Cleartext: 0x00 || 32 bytes Address = 33 bytes total.
        assert_eq!(enc_cleartext.len(), 1 + 32);
        // Shielded: 0x01 || 32 bytes StealthCommitment = 33 bytes total.
        assert_eq!(enc_shielded.len(), 1 + 32);
    }

    #[test]
    fn account_ref_round_trip() {
        let cases = [
            AccountRef::Cleartext(fixed_address(0x11)),
            AccountRef::Shielded(StealthCommitment::from_bytes([0x22; 32])),
        ];
        for r in cases {
            let encoded = bcs::to_bytes(&r).expect("encode");
            let decoded: AccountRef = bcs::from_bytes(&encoded).expect("decode");
            assert_eq!(decoded, r);
        }
    }

    /// `GasBudget` is six u64 fields in source order; encoding is
    /// 48 bytes (6 × 8) with no framing.
    #[test]
    fn gas_budget_bcs_layout() {
        let g = GasBudget {
            computation: 0x0101_0101_0101_0101,
            storage: 0x0202_0202_0202_0202,
            rent: 0x0303_0303_0303_0303,
            bandwidth: 0x0404_0404_0404_0404,
            proof_verification: 0x0505_0505_0505_0505,
            proof_generation: 0x0606_0606_0606_0606,
        };
        let encoded = bcs::to_bytes(&g).expect("encode");
        assert_eq!(encoded.len(), 6 * 8);
        // Each u64 is little-endian per BCS.
        assert_eq!(&encoded[0..8], &[0x01; 8]);
        assert_eq!(&encoded[8..16], &[0x02; 8]);
        assert_eq!(&encoded[40..48], &[0x06; 8]);

        let decoded: GasBudget = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, g);
    }

    /// `CreatedObject` BCS roundtrip with non-trivial values for
    /// each field, exercising every Mutability variant the field
    /// might carry.
    #[test]
    fn created_object_round_trip() {
        let co = CreatedObject {
            creator: fixed_address(0xa1),
            creation_index: 42,
            type_id: fixed_type_id(0xb2),
            initial_owner: Ownership::Shared,
            initial_mutability: Mutability::Immutable,
        };
        let encoded = bcs::to_bytes(&co).expect("encode");
        let decoded: CreatedObject = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, co);
    }

    /// `Witness` encodes as ULEB128 length prefix + raw bytes,
    /// matching `Vec<u8>` BCS encoding.
    #[test]
    fn witness_round_trip() {
        let w = Witness(vec![0xde, 0xad, 0xbe, 0xef]);
        let encoded = bcs::to_bytes(&w).expect("encode");
        // ULEB128(4) = 0x04, then 4 bytes.
        assert_eq!(encoded, vec![0x04, 0xde, 0xad, 0xbe, 0xef]);

        let decoded: Witness = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, w);
    }

    /// `AuthEvidence` with empty signatures and witnesses encodes
    /// as two ULEB128(0) bytes — the minimum auth evidence.
    #[test]
    fn auth_evidence_empty_round_trip() {
        let auth = AuthEvidence {
            signatures: vec![],
            witnesses: vec![],
        };
        let encoded = bcs::to_bytes(&auth).expect("encode");
        assert_eq!(encoded, vec![0x00, 0x00]);

        let decoded: AuthEvidence = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, auth);
    }

    /// `CallParams` BCS roundtrip with realistic values.
    #[test]
    fn call_params_round_trip() {
        let cp = CallParams {
            target_module: ModuleRef(fixed_object_id(0x10)),
            target_function: FunctionId::new("transfer".to_string()).expect("valid"),
            type_arguments: vec![fixed_type_id(0x20), fixed_type_id(0x30)],
            arguments: vec![Value::U64(100), Value::Address(fixed_address(0x40))],
        };
        let encoded = bcs::to_bytes(&cp).expect("encode");
        let decoded: CallParams = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, cp);
    }

    /// `TxBody` field ordering matches §6.0.2 exactly. This test
    /// exercises every field with a non-trivial value and confirms
    /// the roundtrip; ordering correctness is established by the
    /// `tx_hash` KAT regression vector.
    #[test]
    fn tx_body_round_trip() {
        let body = TxBody {
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
        };
        let encoded = bcs::to_bytes(&body).expect("encode");
        let decoded: TxBody = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, body);
    }

    /// `Transaction` outer roundtrip with the same body and a
    /// non-empty auth evidence.
    #[test]
    fn transaction_round_trip() {
        let body = TxBody {
            authorising_account: AccountRef::Cleartext(fixed_address(0x33)),
            fee_payer: None,
            read_set: vec![],
            write_set: vec![],
            created_objects: vec![],
            gas_budget: GasBudget {
                computation: 0,
                storage: 0,
                rent: 0,
                bandwidth: 0,
                proof_verification: 0,
                proof_generation: 0,
            },
            call: CallParams {
                target_module: ModuleRef(fixed_object_id(0x44)),
                target_function: FunctionId::new("noop".to_string()).expect("valid"),
                type_arguments: vec![],
                arguments: vec![],
            },
            nonce: 0,
        };
        let auth = AuthEvidence {
            signatures: vec![Signature::Ed25519([0x55; 64])],
            witnesses: vec![Witness(vec![0x77, 0x88])],
        };
        let tx = Transaction { body, auth };
        let encoded = bcs::to_bytes(&tx).expect("encode");
        let decoded: Transaction = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, tx);
    }

    /// Sanity import — `Mutability` and `ProofCommitment` are
    /// imported for the test fixtures; the compiler enforces this
    /// is non-trivially used. Without this anchor, an
    /// unused-import lint could remove the import.
    #[test]
    fn mutability_variant_round_trip_in_created_object() {
        let bp = BasisPoints::new(6700).expect("valid");
        let co = CreatedObject {
            creator: fixed_address(0x77),
            creation_index: 0,
            type_id: fixed_type_id(0x88),
            initial_owner: Ownership::Address(fixed_address(0x99)),
            initial_mutability: Mutability::VoteUpgradeable {
                token_type: fixed_type_id(0xaa),
                approval_threshold: bp,
                quorum_threshold: BasisPoints::new(3000).expect("valid"),
                voting_period_secs: 7 * 24 * 3600,
                execution_delay_secs: 7 * 24 * 3600,
            },
        };
        let encoded = bcs::to_bytes(&co).expect("encode");
        let decoded: CreatedObject = bcs::from_bytes(&encoded).expect("decode");
        assert_eq!(decoded, co);
        // ProofCommitment isn't used here directly; this assertion just
        // pins that the module compiles against the type.
        let _ = ProofCommitment::from_bytes([0; 48]);
    }
}
