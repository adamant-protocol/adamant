//! Shielded-transaction wire types per whitepaper §7.3.1.
//!
//! Phase 6.8a ships the data-type layer of §7.3 — the
//! [`ShieldedTransaction`] envelope plus its [`PublicInputs`],
//! [`Halo2Proof`], and [`BindingSignature`] components.
//!
//! Phase 6.8b (the actual Halo 2 validity circuit per §7.3.2)
//! lands separately in the new `adamant-halo2` crate per
//! §14.4 Decision 1 (resolved as Path C2 — fork
//! `halo2_gadgets` + necessary `halo2_proofs` subset into an
//! Adamant-owned crate with `PROVENANCE.md`, mirroring Phase
//! 5/5b.1a/b's Sui-Move precedent). The 6.8a wire types here
//! are posture-independent: the proof is treated as opaque bytes
//! at this layer, so adding the circuit later does not require
//! changing the on-chain wire format.
//!
//! # Spec basis
//!
//! Whitepaper §7.3.1 verbatim:
//!
//! > A shielded transaction comprises:
//! >
//! > ```text
//! > ShieldedTransaction {
//! >     nullifiers:        Vec<Nullifier>,        // notes being spent
//! >     output_commitments: Vec<NoteCommitment>,  // notes being created
//! >     encrypted_outputs:  Vec<EncryptedNote>,   // for recipient delivery
//! >     public_inputs:     PublicInputs,          // explicit transaction parameters
//! >     proof:             Halo2Proof,            // attests to validity
//! >     binding_signature: Signature,             // ties the proof to the transaction
//! > }
//! > ```
//! >
//! > Public inputs include the nullifiers, the output
//! > commitments, the GNCT root being spent against, the asset
//! > types involved (which may be partially disclosed for
//! > compliance), and any explicit fees. Everything else is
//! > hidden.
//!
//! # Wire-format strategy
//!
//! - `nullifiers`, `output_commitments`, `encrypted_outputs` are
//!   typed (no opacity needed; their wire shapes are pinned by
//!   Phase 6.2 / 6.1 / 6.7).
//! - `public_inputs` is a structured [`PublicInputs`] type
//!   capturing the §7.3.1 enumeration. Each field is consensus-
//!   binding.
//! - `proof` is the opaque-bytes [`Halo2Proof`] newtype. Phase
//!   6.8b will replace its internal byte representation with a
//!   structured Halo-2-proof shape; the wire format stays
//!   bytes-on-the-wire so on-chain serialization is forward-
//!   compatible.
//! - `binding_signature` is the opaque-bytes [`BindingSignature`]
//!   newtype, holding either an Ed25519 (64 bytes) or ML-DSA-65
//!   (3309 bytes) signature per §3.4 hybrid-signature posture.
//!   The scheme is determined by the holder's selected
//!   spending-authorization mode per §7.2.5 (Ed25519 default,
//!   ML-DSA opt-in).
//!
//! # Cross-references
//!
//! - `Nullifier` per §7.1.2 / Phase 6.2.
//! - `NoteCommitment` per §7.1 / Phase 6.1.
//! - `EncryptedNote` per §7.3.1.1 / Phase 6.7.
//! - `MerkleRoot` per §7.1.3 / Phase 6.3 (used as the
//!   `gnct_root` field of [`PublicInputs`]).
//! - `TypeId` per §5.1.2 / `adamant-types`.

use adamant_types::TypeId;
use serde::{Deserialize, Serialize};

use crate::encrypted_note::EncryptedNote;
use crate::gnct::MerkleRoot;
use crate::note::NoteCommitment;
use crate::nullifier::Nullifier;
use crate::value_commitment::ValueCommitment;

/// A Halo 2 zero-knowledge proof attesting to the validity of a
/// shielded transaction per whitepaper §7.3.1 / §7.3.2.
///
/// Phase 6.8a stores the proof as an opaque byte buffer. Phase
/// 6.8b will replace the internal representation with the
/// structured Halo-2-proof shape from the new `adamant-halo2`
/// fork per §14.4 Decision 1 (resolved as Path C2). The on-chain
/// wire format stays bytes-on-the-wire, so adding the structured
/// shape does NOT require a hard fork of the
/// `ShieldedTransaction` envelope.
///
/// Per §7.3.1: "Halo 2's `PLONKish` arithmetisation … proof size
/// is approximately 1–4 KB depending on the complexity of the
/// shielded computation."
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct Halo2Proof {
    /// Opaque proof bytes. Format is defined by the proving
    /// system selected at Phase 6.8b plan-gate. Until then, the
    /// proof is a placeholder — production-side prove/verify
    /// stubs panic if invoked, surfacing the absent posture
    /// decision early.
    pub bytes: Vec<u8>,
}

impl Halo2Proof {
    /// Construct from raw proof bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the raw proof bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the proof byte buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// A signature binding the [`Halo2Proof`] to the rest of the
/// shielded-transaction wire data per whitepaper §7.3.1.
///
/// Prevents proof malleability: an adversary cannot lift a valid
/// proof from one transaction context and attach it to another.
/// The signature is over a transcript that includes the proof
/// bytes plus the BCS-encoded public inputs.
///
/// Per §3.4 + §7.2.5 hybrid-signature posture, the holder may
/// select Ed25519 (64 bytes; default for routine spending) or
/// ML-DSA-65 (3309 bytes; opt-in for elevated threat models).
/// Phase 6.8a stores the signature as opaque bytes; the scheme
/// tag travels with the signature in the transaction-layer
/// authorization-evidence shape (Phase 7+ wiring).
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct BindingSignature {
    /// Opaque signature bytes per the holder-selected scheme.
    pub bytes: Vec<u8>,
}

impl BindingSignature {
    /// Construct from raw signature bytes.
    #[must_use]
    pub const fn from_bytes(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    /// Borrow the raw signature bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    /// Length in bytes.
    #[must_use]
    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    /// Whether the signature byte buffer is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

/// The public inputs to a shielded-transaction validity proof
/// per whitepaper §7.3.1 (post-amendment instance 33).
///
/// > Public inputs include the nullifiers, the output
/// > commitments, the input and output value commitments, the
/// > GNCT root being spent against, the asset types involved
/// > (which may be partially disclosed for compliance), and
/// > any explicit fees. Everything else is hidden.
///
/// The `nullifiers`, `output_commitments`,
/// `input_value_commitments`, and `output_value_commitments`
/// are duplicated between the [`ShieldedTransaction`] envelope
/// and its `public_inputs`: they appear twice because they are
/// both part of the public input vector that Halo 2 verification
/// consumes AND part of the on-chain consensus-checked fields
/// (the nullifier set, GNCT update, and homomorphic balance
/// check). §7.3.1 lists them in both roles. The duplication is
/// consensus-binding; a transaction with a mismatch is invalid.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct PublicInputs {
    /// Nullifiers being published (= notes being spent). Same
    /// values as the `ShieldedTransaction.nullifiers` field;
    /// duplicated here per §7.3.1.
    pub nullifiers: Vec<Nullifier>,
    /// Per-input value commitments per §7.3.1.2 (post-amendment
    /// instance 33). Parallel to [`Self::nullifiers`] (index
    /// `i` of one corresponds to index `i` of the other). Used
    /// by the §7.3.2 statement 4 chain-level homomorphic
    /// balance check.
    pub input_value_commitments: Vec<ValueCommitment>,
    /// Output note commitments being created (= notes coming
    /// into existence). Same values as the
    /// `ShieldedTransaction.output_commitments` field;
    /// duplicated here per §7.3.1.
    pub output_commitments: Vec<NoteCommitment>,
    /// Per-output value commitments per §7.3.1.2 (post-amendment
    /// instance 33). Parallel to [`Self::output_commitments`]
    /// (same index correspondence).
    pub output_value_commitments: Vec<ValueCommitment>,
    /// The GNCT root being spent against per §7.1.3. The proof
    /// asserts every input note's existence in the tree under
    /// this root. Each shielded transaction picks ONE root from
    /// the recent-roots window (§7.1.3) and proves all its
    /// inputs under that single root.
    pub gnct_root: MerkleRoot,
    /// Asset types involved in the transaction. May be partially
    /// disclosed for compliance per §7.3.1. An empty vector
    /// means full asset-type privacy (the proof commits to
    /// asset types that are entirely hidden).
    pub disclosed_asset_types: Vec<TypeId>,
    /// Explicit transaction fees per asset type. The fee is the
    /// amount in the asset's smallest unit. Disclosed for fee-
    /// payer auditing and for validators to verify economic
    /// invariants; the §7.3.2 statement 4 (value conservation)
    /// covers the implicit-fee case.
    pub explicit_fees: Vec<FeeEntry>,
}

/// A single entry in the [`PublicInputs::explicit_fees`] vector
/// per §7.3.1 + §10.2.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct FeeEntry {
    /// Asset type the fee is paid in.
    pub asset_type: TypeId,
    /// Amount in the asset's smallest unit.
    pub amount: u64,
}

impl FeeEntry {
    /// Construct from components.
    #[must_use]
    pub const fn new(asset_type: TypeId, amount: u64) -> Self {
        Self { asset_type, amount }
    }
}

/// A shielded transaction per whitepaper §7.3.1.
///
/// On-chain, this struct's BCS encoding is consensus-binding:
/// validators verify that (a) every nullifier is fresh against
/// the chain's nullifier set, (b) the [`Halo2Proof`] is valid
/// against the [`PublicInputs`], (c) the [`BindingSignature`] is
/// valid over `(proof || BCS(public_inputs))` under the
/// authorization-mode-selected key, and (d) the
/// `output_commitments` are appended to the GNCT.
///
/// Phase 6.8a ships the type. Phase 6.8b ships the prover/
/// verifier circuit. Phase 7+ wires this struct into the
/// transaction-layer dispatch path.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ShieldedTransaction {
    /// Nullifiers for input notes being spent per §7.1.2.
    pub nullifiers: Vec<Nullifier>,
    /// Per-input value commitments per §7.3.1.2 (post-amendment
    /// instance 33). Parallel to [`Self::nullifiers`] (index
    /// `i` of one corresponds to index `i` of the other).
    pub input_value_commitments: Vec<ValueCommitment>,
    /// Output note commitments for notes being created per §7.1.
    pub output_commitments: Vec<NoteCommitment>,
    /// Per-output value commitments per §7.3.1.2 (post-amendment
    /// instance 33). Parallel to [`Self::output_commitments`].
    pub output_value_commitments: Vec<ValueCommitment>,
    /// Encrypted-note envelopes for recipient delivery per
    /// §7.3.1.1. One per output commitment, in the same order.
    pub encrypted_outputs: Vec<EncryptedNote>,
    /// Public inputs to the validity proof per §7.3.1.
    pub public_inputs: PublicInputs,
    /// Halo 2 zero-knowledge proof attesting to the §7.3.2
    /// statements per §7.3.1.
    pub proof: Halo2Proof,
    /// Binding signature tying the proof to the transaction
    /// per §7.3.1, preventing proof malleability. Per §7.3.1.2,
    /// the binding signature also commits to the randomness sum
    /// `r_balance = Σ r_in - Σ r_out`, completing the §7.3.2
    /// statement 4 balance attestation.
    pub binding_signature: BindingSignature,
}

impl ShieldedTransaction {
    /// Construct from components. Bypasses any cross-field
    /// consistency check; consensus-side validators perform
    /// those checks at admission time per §7.3.2.
    ///
    /// The 8-argument signature mirrors the §7.3.1 wire-type
    /// shape verbatim — each field on the spec's
    /// `ShieldedTransaction` struct gets one argument.
    /// Refactoring into a builder is deferred until a real
    /// constructor pain-point emerges; the spec-faithful
    /// shape is more auditable today.
    #[must_use]
    #[allow(clippy::too_many_arguments)]
    pub const fn new(
        nullifiers: Vec<Nullifier>,
        input_value_commitments: Vec<ValueCommitment>,
        output_commitments: Vec<NoteCommitment>,
        output_value_commitments: Vec<ValueCommitment>,
        encrypted_outputs: Vec<EncryptedNote>,
        public_inputs: PublicInputs,
        proof: Halo2Proof,
        binding_signature: BindingSignature,
    ) -> Self {
        Self {
            nullifiers,
            input_value_commitments,
            output_commitments,
            output_value_commitments,
            encrypted_outputs,
            public_inputs,
            proof,
            binding_signature,
        }
    }

    /// Number of input notes being spent.
    #[must_use]
    pub fn input_count(&self) -> usize {
        self.nullifiers.len()
    }

    /// Number of output notes being created.
    #[must_use]
    pub fn output_count(&self) -> usize {
        self.output_commitments.len()
    }

    /// Whether the envelope-layer cross-field shape is locally
    /// consistent:
    ///
    /// - `encrypted_outputs.len() == output_commitments.len()`,
    /// - `input_value_commitments.len() == nullifiers.len()`
    ///   (one input value commitment per nullifier per §7.3.1),
    /// - `output_value_commitments.len() == output_commitments.len()`
    ///   (one output value commitment per output note per §7.3.1),
    /// - `public_inputs.nullifiers == nullifiers`,
    /// - `public_inputs.output_commitments == output_commitments`,
    /// - `public_inputs.input_value_commitments == input_value_commitments`,
    /// - `public_inputs.output_value_commitments == output_value_commitments`.
    ///
    /// This is a **structural** check only — it does NOT verify
    /// the proof, nullifier-uniqueness, value conservation, or
    /// any of the §7.3.2 cryptographic statements. Consensus-
    /// side admission (Phase 7+) performs those checks.
    #[must_use]
    pub fn is_locally_consistent(&self) -> bool {
        self.encrypted_outputs.len() == self.output_commitments.len()
            && self.input_value_commitments.len() == self.nullifiers.len()
            && self.output_value_commitments.len() == self.output_commitments.len()
            && self.public_inputs.nullifiers == self.nullifiers
            && self.public_inputs.output_commitments == self.output_commitments
            && self.public_inputs.input_value_commitments == self.input_value_commitments
            && self.public_inputs.output_value_commitments == self.output_value_commitments
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use adamant_crypto::ml_kem::DecapsulationKey;
    use getrandom::{rand_core::UnwrapErr, SysRng};

    use crate::encrypted_note::encrypt_note_for_recipient;
    use crate::nullifier::LeafPosition;

    fn fresh_encrypted_output(position: LeafPosition) -> EncryptedNote {
        let dk = DecapsulationKey::from_seed(&[0xA1; 64]);
        let ek = dk.encapsulation_key();
        let payload = b"sample-shielded-payload";
        let mut rng = UnwrapErr(SysRng);
        let (envelope, _) = encrypt_note_for_recipient(&ek, position, payload, &mut rng);
        envelope
    }

    fn sample_public_inputs(
        nullifiers: Vec<Nullifier>,
        output_commitments: Vec<NoteCommitment>,
        input_value_commitments: Vec<ValueCommitment>,
        output_value_commitments: Vec<ValueCommitment>,
    ) -> PublicInputs {
        PublicInputs {
            nullifiers,
            input_value_commitments,
            output_commitments,
            output_value_commitments,
            gnct_root: MerkleRoot::from_bytes([0x42; 32]),
            disclosed_asset_types: vec![TypeId::from_bytes([0x55; 32])],
            explicit_fees: vec![FeeEntry::new(TypeId::from_bytes([0x55; 32]), 100)],
        }
    }

    fn sample_transaction() -> ShieldedTransaction {
        let nullifiers = vec![
            Nullifier::from_bytes([0x11; 32]),
            Nullifier::from_bytes([0x22; 32]),
        ];
        let output_commitments = vec![
            NoteCommitment::from_bytes([0x33; 32]),
            NoteCommitment::from_bytes([0x44; 32]),
        ];
        let input_value_commitments = vec![
            ValueCommitment::from_bytes([0x66; 32]),
            ValueCommitment::from_bytes([0x77; 32]),
        ];
        let output_value_commitments = vec![
            ValueCommitment::from_bytes([0x88; 32]),
            ValueCommitment::from_bytes([0x99; 32]),
        ];
        let encrypted_outputs = vec![
            fresh_encrypted_output(LeafPosition(0)),
            fresh_encrypted_output(LeafPosition(1)),
        ];
        let public_inputs = sample_public_inputs(
            nullifiers.clone(),
            output_commitments.clone(),
            input_value_commitments.clone(),
            output_value_commitments.clone(),
        );
        ShieldedTransaction::new(
            nullifiers,
            input_value_commitments,
            output_commitments,
            output_value_commitments,
            encrypted_outputs,
            public_inputs,
            Halo2Proof::from_bytes(vec![0xAA; 1024]),
            BindingSignature::from_bytes(vec![0xBB; 64]),
        )
    }

    // ---------- Type-shape tests ----------

    #[test]
    fn halo2_proof_round_trips_bytes() {
        let p = Halo2Proof::from_bytes(vec![0xAB; 100]);
        assert_eq!(p.as_bytes(), &[0xAB; 100]);
        assert_eq!(p.len(), 100);
        assert!(!p.is_empty());
        assert!(Halo2Proof::from_bytes(Vec::new()).is_empty());
    }

    #[test]
    fn binding_signature_round_trips_bytes() {
        let s = BindingSignature::from_bytes(vec![0xCD; 64]);
        assert_eq!(s.as_bytes(), &[0xCD; 64]);
        assert_eq!(s.len(), 64);
    }

    #[test]
    fn fee_entry_components() {
        let asset = TypeId::from_bytes([0xEE; 32]);
        let fee = FeeEntry::new(asset, 1234);
        assert_eq!(fee.asset_type, asset);
        assert_eq!(fee.amount, 1234);
    }

    #[test]
    fn public_inputs_field_shapes() {
        let nullifiers = vec![Nullifier::from_bytes([0x01; 32])];
        let commitments = vec![NoteCommitment::from_bytes([0x02; 32])];
        let input_vcs = vec![ValueCommitment::from_bytes([0x06; 32])];
        let output_vcs = vec![ValueCommitment::from_bytes([0x07; 32])];
        let pi = sample_public_inputs(
            nullifiers.clone(),
            commitments.clone(),
            input_vcs.clone(),
            output_vcs.clone(),
        );
        assert_eq!(pi.nullifiers, nullifiers);
        assert_eq!(pi.output_commitments, commitments);
        assert_eq!(pi.input_value_commitments, input_vcs);
        assert_eq!(pi.output_value_commitments, output_vcs);
        assert_eq!(pi.gnct_root.to_bytes(), [0x42; 32]);
        assert_eq!(pi.disclosed_asset_types.len(), 1);
        assert_eq!(pi.explicit_fees.len(), 1);
        assert_eq!(pi.explicit_fees[0].amount, 100);
    }

    /// Mismatched `input_value_commitments` count breaks local
    /// consistency.
    #[test]
    fn local_consistency_fails_on_input_vc_count_mismatch() {
        let mut tx = sample_transaction();
        tx.input_value_commitments.pop();
        assert!(!tx.is_locally_consistent());
    }

    /// Mismatched `output_value_commitments` count breaks
    /// local consistency.
    #[test]
    fn local_consistency_fails_on_output_vc_count_mismatch() {
        let mut tx = sample_transaction();
        tx.output_value_commitments.pop();
        assert!(!tx.is_locally_consistent());
    }

    /// Mismatched `public_inputs.input_value_commitments`
    /// breaks local consistency.
    #[test]
    fn local_consistency_fails_on_public_inputs_input_vc_mismatch() {
        let mut tx = sample_transaction();
        tx.public_inputs.input_value_commitments[0] = ValueCommitment::from_bytes([0xFF; 32]);
        assert!(!tx.is_locally_consistent());
    }

    #[test]
    fn shielded_transaction_input_output_counts() {
        let tx = sample_transaction();
        assert_eq!(tx.input_count(), 2);
        assert_eq!(tx.output_count(), 2);
    }

    // ---------- Cross-field consistency ----------

    #[test]
    fn locally_consistent_passes_for_well_formed_tx() {
        let tx = sample_transaction();
        assert!(tx.is_locally_consistent());
    }

    /// Mismatched `encrypted_outputs` count breaks local
    /// consistency.
    #[test]
    fn local_consistency_fails_on_encrypted_outputs_count_mismatch() {
        let mut tx = sample_transaction();
        tx.encrypted_outputs.pop();
        assert!(!tx.is_locally_consistent());
    }

    /// Mismatched `public_inputs.nullifiers` breaks local
    /// consistency.
    #[test]
    fn local_consistency_fails_on_public_inputs_nullifier_mismatch() {
        let mut tx = sample_transaction();
        tx.public_inputs
            .nullifiers
            .push(Nullifier::from_bytes([0xFF; 32]));
        assert!(!tx.is_locally_consistent());
    }

    /// Mismatched `public_inputs.output_commitments` breaks
    /// local consistency.
    #[test]
    fn local_consistency_fails_on_public_inputs_commitment_mismatch() {
        let mut tx = sample_transaction();
        tx.public_inputs.output_commitments[0] = NoteCommitment::from_bytes([0xFF; 32]);
        assert!(!tx.is_locally_consistent());
    }

    // ---------- BCS round-trip ----------

    #[test]
    fn shielded_transaction_bcs_round_trip() {
        let original = sample_transaction();
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: ShieldedTransaction = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn public_inputs_bcs_round_trip() {
        let original = sample_public_inputs(
            vec![Nullifier::from_bytes([0x01; 32])],
            vec![NoteCommitment::from_bytes([0x02; 32])],
            vec![ValueCommitment::from_bytes([0x06; 32])],
            vec![ValueCommitment::from_bytes([0x07; 32])],
        );
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: PublicInputs = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn halo2_proof_bcs_round_trip() {
        let original = Halo2Proof::from_bytes(vec![0x01; 1500]);
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: Halo2Proof = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn binding_signature_bcs_round_trip() {
        let original = BindingSignature::from_bytes(vec![0x02; 64]);
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: BindingSignature = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    #[test]
    fn fee_entry_bcs_round_trip() {
        let original = FeeEntry::new(TypeId::from_bytes([0x03; 32]), u64::MAX);
        let encoded = bcs::to_bytes(&original).unwrap();
        let decoded: FeeEntry = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(original, decoded);
    }

    /// Empty-collection edge cases must round-trip cleanly so a
    /// no-op shielded transaction (e.g., a fee-only tx with no
    /// inputs / outputs, hypothetical) doesn't break BCS.
    #[test]
    fn shielded_transaction_empty_collections_bcs_round_trip() {
        let tx = ShieldedTransaction::new(
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            Vec::new(),
            PublicInputs {
                nullifiers: Vec::new(),
                input_value_commitments: Vec::new(),
                output_commitments: Vec::new(),
                output_value_commitments: Vec::new(),
                gnct_root: MerkleRoot::from_bytes([0u8; 32]),
                disclosed_asset_types: Vec::new(),
                explicit_fees: Vec::new(),
            },
            Halo2Proof::from_bytes(Vec::new()),
            BindingSignature::from_bytes(Vec::new()),
        );
        let encoded = bcs::to_bytes(&tx).unwrap();
        let decoded: ShieldedTransaction = bcs::from_bytes(&encoded).unwrap();
        assert_eq!(tx, decoded);
        assert!(tx.is_locally_consistent());
    }
}
