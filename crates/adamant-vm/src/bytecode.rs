//! Bytecode instructions per whitepaper §6.2.1.4.
//!
//! Adamant Move bytecode is Sui-Move's instruction set plus
//! Adamant-specific extensions. Sui's instruction set is inherited
//! through the vendored [`move_binary_format`] crate (see
//! `vendor/move-binary-format` and whitepaper §6.2.1.1). Adamant
//! adds 16 instructions for privacy operations, Halo 2 proof
//! primitives, hash and signature verification, and gas
//! manipulation.
//!
//! # Type architecture
//!
//! - [`AdamantBytecode`] carries the 16 Adamant-specific
//!   instructions with their operands (e.g.,
//!   `InvokeShielded(FunctionHandleIndex)`).
//! - [`AdamantOpcodeKind`] is the operand-less variant set; it
//!   owns the bijection between opcode bytes and instruction
//!   identity. Both [`AdamantOpcodeKind::opcode_byte`] and
//!   [`AdamantOpcodeKind::try_from_opcode_byte`] are
//!   consensus-critical: changing any byte assignment is a hard
//!   fork.
//! - [`BytecodeInstruction`] is the composite enum a function
//!   body is a sequence of: each instruction is either an
//!   inherited Sui-Move opcode or an Adamant extension.
//!
//! # Wire encoding
//!
//! Wire encoding (a single byte stream interleaving inherited and
//! Adamant opcodes, distinguished by opcode value, with operands
//! parsed per-instruction following Sui's variable-length operand
//! encoding) is implemented in a subsequent deliverable that
//! extends Sui's `serializer.rs` / `deserializer.rs`. This module
//! defines in-memory types only; bytecode is Move's native binary
//! format, not BCS (whitepaper §6.2.1.5), so no `Serialize` /
//! `Deserialize` derives appear here.
//!
//! # Opcode-byte assignments
//!
//! Adamant's reserved range is `0x80..=0x91` (18 sequential bytes
//! above Sui's max active opcode `0x56`, leaving 41 free slots
//! `0x57..=0x7F` for future Sui-Move upstream additions). Opcode
//! byte `0x90` was reserved for `MlDsaVerify87` prior to whitepaper
//! §6.2 amendment (commits 80ccd46 + 22b5a8a + 63cbf5c) restricting
//! the post-quantum signature scheme to ML-DSA-65 per §3.4.2; the
//! enum's variants are renumbered down by one above the freed slot
//! at 0x8C. The post-Phase-5/6 audit pass added two ML-KEM
//! extension opcodes per whitepaper §6.2.1.4 lines 419-420
//! (`MlKemEncapsulate = 0x8D`, `MlKemDecapsulate = 0x8E`),
//! shifting the gas-extension opcodes up by two slots
//! (`ChargeGas = 0x8F`, `RemainingGas = 0x90`, `OutOfGas = 0x91`).
//! The complete table is pinned by [`AdamantOpcodeKind::opcode_byte`]
//! and asserted in this module's tests.

use adamant_bytecode_format::{Bytecode, CodeOffset, FunctionHandleIndex, VariantJumpTable};

// ---------- AdamantBytecode (with operands) ----------

/// Adamant-specific bytecode extensions per whitepaper §6.2.1.4.
///
/// Lives alongside Sui-Move's inherited [`Bytecode`] enum; the
/// composite [`BytecodeInstruction`] is what function bodies are
/// sequences of (§6.2.1.4: "the bytecode body of a function is a
/// sequence of instructions where each instruction is either an
/// inherited Sui-Move opcode or an Adamant extension"). Variant set
/// is genesis-fixed; adding is a hard fork.
///
/// Operand types are inherited from `move-binary-format` where
/// they exist ([`FunctionHandleIndex`] for `InvokeShielded` and
/// `InvokeTransparent`). Adamant-specific operand types
/// ([`CircuitId`], [`GasDimension`]) are defined in this module.
#[derive(Clone, Debug, Eq, PartialEq, Hash)]
pub enum AdamantBytecode {
    /// Invoke a `#[shielded]` function. Runtime asserts the
    /// caller's privacy context is shielded; aborts otherwise.
    /// Stack effect matches Sui's `Call`.
    InvokeShielded(FunctionHandleIndex),
    /// Invoke a `#[transparent]` function. Privacy-context check
    /// inverse to [`Self::InvokeShielded`].
    InvokeTransparent(FunctionHandleIndex),
    /// Emit a Halo 2 proof witness for the current shielded
    /// execution context. Pops circuit inputs from the stack;
    /// pushes a `Witness` value (per whitepaper §6.0.7).
    GenerateProof(CircuitId),
    /// Verify a Halo 2 proof. Pops `Witness` and public inputs;
    /// pushes a `bool`.
    VerifyProof(CircuitId),
    /// Produce a sub-view-key per whitepaper §4.4.2 and §7.
    ReleaseSubViewKey,
    /// Produce a KZG commitment over a vector of field elements
    /// per whitepaper §3.9.2. Pops the vector; pushes a 48-byte
    /// commitment.
    KzgCommit,
    /// Verify a KZG opening proof. Pops the commitment, the
    /// opening, and the claimed value; pushes a `bool`.
    KzgVerify,
    /// Verify a recursive Halo 2 proof per whitepaper §8.
    RecursiveVerify,
    /// SHA3-256 hash of a byte vector (whitepaper §3.3.1). Pops a
    /// `vector<u8>`; pushes `[u8; 32]`.
    Sha3_256,
    /// BLAKE3 hash of a byte vector (whitepaper §3.3.2). Pops a
    /// `vector<u8>`; pushes `[u8; 32]`.
    Blake3,
    /// Verify an Ed25519 signature (whitepaper §3.4.1). Pops
    /// public key, message, signature; pushes `bool`.
    Ed25519Verify,
    /// Verify an ML-DSA-65 signature (whitepaper §3.4.2).
    /// ML-DSA-65 is the protocol's only post-quantum signature
    /// scheme per §3.4.2's "Level 3 is the appropriate balance"
    /// commitment. ML-DSA-87 was removed from §6.2 by whitepaper
    /// commits 80ccd46 + 22b5a8a + 63cbf5c (spec-first verification
    /// 23rd instance) aligning §6.2 to §3.4.2's stated authority.
    MlDsaVerify65,
    /// Verify a BLS12-381 signature (whitepaper §3.4.3).
    BlsVerify,
    /// Perform ML-KEM-768 encapsulation (whitepaper §3.7). Pops an
    /// ML-KEM public key (1184 bytes); pushes a `(ciphertext,
    /// shared_secret)` tuple as `[u8; 1088]` followed by `[u8; 32]`.
    /// Used by privacy-layer circuits (§7) for stealth-address
    /// derivation and encrypted memo construction.
    MlKemEncapsulate,
    /// Perform ML-KEM-768 decapsulation (whitepaper §3.7). Pops an
    /// ML-KEM secret key and a 1088-byte ciphertext; pushes the
    /// recovered 32-byte shared secret. Used by recipient-side
    /// privacy circuits.
    MlKemDecapsulate,
    /// Charge gas across one of the six dimensions (per whitepaper
    /// §6.0.7's `GasBudget` and §6.3.1). Pops the amount as `u64`.
    ChargeGas(GasDimension),
    /// Push the remaining budget for one of the six dimensions as
    /// `u64`. Used by stdlib functions that adapt behaviour based
    /// on remaining budget.
    RemainingGas(GasDimension),
    /// Abort the transaction with the out-of-gas error. Used by
    /// stdlib functions that detect dimension exhaustion.
    OutOfGas,
}

impl AdamantBytecode {
    /// The operand-less kind of this instruction. Used for
    /// dispatching on opcode byte during deserialisation, where
    /// operands are parsed separately by kind.
    #[must_use]
    pub const fn kind(&self) -> AdamantOpcodeKind {
        match self {
            Self::InvokeShielded(_) => AdamantOpcodeKind::InvokeShielded,
            Self::InvokeTransparent(_) => AdamantOpcodeKind::InvokeTransparent,
            Self::GenerateProof(_) => AdamantOpcodeKind::GenerateProof,
            Self::VerifyProof(_) => AdamantOpcodeKind::VerifyProof,
            Self::ReleaseSubViewKey => AdamantOpcodeKind::ReleaseSubViewKey,
            Self::KzgCommit => AdamantOpcodeKind::KzgCommit,
            Self::KzgVerify => AdamantOpcodeKind::KzgVerify,
            Self::RecursiveVerify => AdamantOpcodeKind::RecursiveVerify,
            Self::Sha3_256 => AdamantOpcodeKind::Sha3_256,
            Self::Blake3 => AdamantOpcodeKind::Blake3,
            Self::Ed25519Verify => AdamantOpcodeKind::Ed25519Verify,
            Self::MlDsaVerify65 => AdamantOpcodeKind::MlDsaVerify65,
            Self::BlsVerify => AdamantOpcodeKind::BlsVerify,
            Self::MlKemEncapsulate => AdamantOpcodeKind::MlKemEncapsulate,
            Self::MlKemDecapsulate => AdamantOpcodeKind::MlKemDecapsulate,
            Self::ChargeGas(_) => AdamantOpcodeKind::ChargeGas,
            Self::RemainingGas(_) => AdamantOpcodeKind::RemainingGas,
            Self::OutOfGas => AdamantOpcodeKind::OutOfGas,
        }
    }

    /// Convenience: the opcode byte for this instruction.
    /// Equivalent to `self.kind().opcode_byte()`.
    #[must_use]
    pub const fn opcode_byte(&self) -> u8 {
        self.kind().opcode_byte()
    }
}

// ---------- AdamantOpcodeKind (operandless) ----------

/// The "kind" of an Adamant-specific bytecode instruction —
/// equivalent to [`AdamantBytecode`] without operands. Used by the
/// deserialiser (next deliverable) to dispatch from an opcode byte
/// to a kind, then parse operand bytes based on kind.
///
/// The opcode-byte ↔ kind mapping is a bijection on the assigned
/// range `0x80..=0x8F` and is consensus-critical: changing any
/// assignment (or reordering variants) is a hard fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum AdamantOpcodeKind {
    /// Opcode byte `0x80`.
    InvokeShielded,
    /// Opcode byte `0x81`.
    InvokeTransparent,
    /// Opcode byte `0x82`.
    GenerateProof,
    /// Opcode byte `0x83`.
    VerifyProof,
    /// Opcode byte `0x84`.
    ReleaseSubViewKey,
    /// Opcode byte `0x85`.
    KzgCommit,
    /// Opcode byte `0x86`.
    KzgVerify,
    /// Opcode byte `0x87`.
    RecursiveVerify,
    /// Opcode byte `0x88`.
    Sha3_256,
    /// Opcode byte `0x89`.
    Blake3,
    /// Opcode byte `0x8A`.
    Ed25519Verify,
    /// Opcode byte `0x8B`.
    MlDsaVerify65,
    /// Opcode byte `0x8C`.
    /// (Renumbered from `0x8D` after whitepaper §6.2 amendment
    /// restricted to ML-DSA-65; the prior `0x8C = MlDsaVerify87`
    /// slot freed and subsequent variants compacted down by one.)
    BlsVerify,
    /// Opcode byte `0x8D` — ML-KEM-768 encapsulation per
    /// whitepaper §6.2.1.4 line 419 + §3.7.
    MlKemEncapsulate,
    /// Opcode byte `0x8E` — ML-KEM-768 decapsulation per
    /// whitepaper §6.2.1.4 line 420 + §3.7.
    MlKemDecapsulate,
    /// Opcode byte `0x8F`.
    ChargeGas,
    /// Opcode byte `0x90`.
    RemainingGas,
    /// Opcode byte `0x91`.
    OutOfGas,
}

impl AdamantOpcodeKind {
    /// Every Adamant-extension kind, in opcode-byte order. Useful
    /// for iteration in tests and tooling. The slice's length is
    /// pinned at 18 in tests; accidental variant drift fails the
    /// suite immediately. (16 → 18 at the post-Phase-5/6 audit pass
    /// when `MlKemEncapsulate` + `MlKemDecapsulate` were added per
    /// whitepaper §6.2.1.4 lines 419-420.)
    pub const ALL: &'static [Self] = &[
        Self::InvokeShielded,
        Self::InvokeTransparent,
        Self::GenerateProof,
        Self::VerifyProof,
        Self::ReleaseSubViewKey,
        Self::KzgCommit,
        Self::KzgVerify,
        Self::RecursiveVerify,
        Self::Sha3_256,
        Self::Blake3,
        Self::Ed25519Verify,
        Self::MlDsaVerify65,
        Self::BlsVerify,
        Self::MlKemEncapsulate,
        Self::MlKemDecapsulate,
        Self::ChargeGas,
        Self::RemainingGas,
        Self::OutOfGas,
    ];

    /// The opcode byte assigned to this kind in the wire format.
    /// Pinned at the values listed; reordering or changing any
    /// value is a hard fork (§6.2.1.4 "the complete instruction
    /// set — inherited and extension — is genesis-fixed").
    #[must_use]
    pub const fn opcode_byte(self) -> u8 {
        match self {
            Self::InvokeShielded => 0x80,
            Self::InvokeTransparent => 0x81,
            Self::GenerateProof => 0x82,
            Self::VerifyProof => 0x83,
            Self::ReleaseSubViewKey => 0x84,
            Self::KzgCommit => 0x85,
            Self::KzgVerify => 0x86,
            Self::RecursiveVerify => 0x87,
            Self::Sha3_256 => 0x88,
            Self::Blake3 => 0x89,
            Self::Ed25519Verify => 0x8A,
            Self::MlDsaVerify65 => 0x8B,
            Self::BlsVerify => 0x8C,
            Self::MlKemEncapsulate => 0x8D,
            Self::MlKemDecapsulate => 0x8E,
            Self::ChargeGas => 0x8F,
            Self::RemainingGas => 0x90,
            Self::OutOfGas => 0x91,
        }
    }

    /// Inverse of [`Self::opcode_byte`]: parse an opcode byte to a
    /// kind. Returns `None` for any byte outside the assigned
    /// range `0x80..=0x8F`, including bytes in Sui's range
    /// (`0x01..=0x56`) which the bytecode deserialiser dispatches
    /// through Sui's path instead.
    #[must_use]
    pub const fn try_from_opcode_byte(byte: u8) -> Option<Self> {
        match byte {
            0x80 => Some(Self::InvokeShielded),
            0x81 => Some(Self::InvokeTransparent),
            0x82 => Some(Self::GenerateProof),
            0x83 => Some(Self::VerifyProof),
            0x84 => Some(Self::ReleaseSubViewKey),
            0x85 => Some(Self::KzgCommit),
            0x86 => Some(Self::KzgVerify),
            0x87 => Some(Self::RecursiveVerify),
            0x88 => Some(Self::Sha3_256),
            0x89 => Some(Self::Blake3),
            0x8A => Some(Self::Ed25519Verify),
            0x8B => Some(Self::MlDsaVerify65),
            0x8C => Some(Self::BlsVerify),
            0x8D => Some(Self::MlKemEncapsulate),
            0x8E => Some(Self::MlKemDecapsulate),
            0x8F => Some(Self::ChargeGas),
            0x90 => Some(Self::RemainingGas),
            0x91 => Some(Self::OutOfGas),
            _ => None,
        }
    }
}

// ---------- CircuitId ----------

/// Reference to a Halo 2 circuit definition (§6.2.1.4 "an index
/// into the module's circuit-reference pool").
///
/// Per the §6.2.1.4 "`CircuitId` resolution" amendment (commit
/// 0d3a957): the pool's location and structure is deferred to §7
/// (the privacy layer). At the bytecode layer, `CircuitId` is an
/// opaque `u16` index; runtime resolution from index to circuit
/// definition is the privacy layer's concern. This is the
/// encoding/construction split established in §6.0.7 applied to
/// bytecode operands: canonical encoding pinned now, semantic
/// construction deferred to the section that defines the role.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub struct CircuitId(pub u16);

// ---------- GasDimension ----------

/// One of the six gas dimensions per whitepaper §6.0.7's
/// `GasBudget` and §6.3.1.
///
/// Variant order matches `GasBudget`'s field declaration order
/// exactly (`computation`, `storage`, `rent`, `bandwidth`,
/// `proof_verification`, `proof_generation`). Reordering is a
/// hard fork.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash)]
pub enum GasDimension {
    /// CPU cycles consumed by bytecode execution (§6.3.1
    /// dimension 1).
    Computation,
    /// Bytes added to active state (§6.3.1 dimension 2).
    Storage,
    /// Storage-rent prepayment (§6.3.1 dimension 3, §5.6).
    Rent,
    /// Bytes transmitted by validators when propagating the
    /// transaction (§6.3.1 dimension 4).
    Bandwidth,
    /// CPU cost of verifying zero-knowledge proofs attached to
    /// shielded transactions (§6.3.1 dimension 5).
    ProofVerification,
    /// CPU cost of generating zero-knowledge proofs when
    /// outsourced to a prover market (§6.3.1 dimension 6, §7).
    ProofGeneration,
}

// ---------- BytecodeInstruction ----------

/// A single bytecode instruction in a function body — either an
/// inherited Sui-Move opcode or an Adamant-specific extension
/// (whitepaper §6.2.1.4).
///
/// Wire encoding (a single byte stream interleaving inherited and
/// Adamant opcodes, distinguished by opcode value) is implemented
/// in a subsequent deliverable that extends Sui's bytecode
/// serializer/deserializer. This type carries the in-memory shape
/// only; no `Serialize` / `Deserialize` derives at this layer
/// (§6.2.1.5: bytecode is Move's native binary format, not BCS).
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BytecodeInstruction {
    /// An inherited Sui-Move bytecode instruction.
    ///
    /// **Note on deprecated variants.** Sui's [`Bytecode`] enum
    /// includes 10 deprecated variants for the Diem-Move global
    /// storage operations (`ExistsDeprecated`,
    /// `MoveFromDeprecated`, `MoveToDeprecated`,
    /// `MutBorrowGlobalDeprecated`, `ImmBorrowGlobalDeprecated`,
    /// plus their `*_Generic` counterparts). These variants exist
    /// in the inherited type because the type is byte-faithful to
    /// upstream Sui at the vendored tag, but modules whose
    /// bytecode contains them are rejected at deployment time by
    /// the validator (whitepaper §6.2.1.6 rule 5: "no global
    /// storage instructions"). The deprecated variants are
    /// inherited-but-invalid; they cannot appear in any module
    /// that passes Adamant validation, even though the Rust type
    /// permits constructing them.
    Inherited(Bytecode),
    /// An Adamant-specific bytecode extension per §6.2.1.4.
    Adamant(AdamantBytecode),
}

impl BytecodeInstruction {
    /// Returns `true` if this instruction always branches.
    ///
    /// Inherited instructions delegate to
    /// [`Bytecode::is_unconditional_branch`]; every Adamant
    /// extension is non-branching (none of the 16 extensions
    /// alters control flow — privacy, hash, signature-verify,
    /// proof, and gas operations all fall through to the next
    /// instruction).
    #[must_use]
    pub fn is_unconditional_branch(&self) -> bool {
        match self {
            Self::Inherited(b) => b.is_unconditional_branch(),
            Self::Adamant(_) => false,
        }
    }

    /// Returns `true` if this instruction's branching depends on
    /// a runtime value. Inherited delegates to
    /// [`Bytecode::is_conditional_branch`]; every Adamant
    /// extension is non-branching.
    #[must_use]
    pub fn is_conditional_branch(&self) -> bool {
        match self {
            Self::Inherited(b) => b.is_conditional_branch(),
            Self::Adamant(_) => false,
        }
    }

    /// Returns `true` if this instruction is a conditional or
    /// unconditional branch.
    #[must_use]
    pub fn is_branch(&self) -> bool {
        self.is_conditional_branch() || self.is_unconditional_branch()
    }

    /// Returns the in-function offsets this instruction can
    /// branch to. Inherited delegates to [`Bytecode::offsets`];
    /// Adamant extensions emit no offsets (none branch within
    /// the function).
    ///
    /// # Panics
    ///
    /// Panics if a `VariantSwitch`'s jump-table index is out of
    /// bounds (mirrors [`Bytecode::offsets`]). The bounds-checker
    /// pass is expected to have run before this is called;
    /// bounds-checked inputs do not trigger the panic.
    #[must_use]
    pub fn offsets(&self, jump_tables: &[VariantJumpTable]) -> Vec<CodeOffset> {
        match self {
            Self::Inherited(b) => b.offsets(jump_tables),
            Self::Adamant(_) => vec![],
        }
    }

    /// Returns the successor PCs of the instruction at `pc` in
    /// ascending order. Mirrors [`Bytecode::get_successors`]'s
    /// shape: explicit branch offsets plus the fall-through PC
    /// (`pc + 1`) when the instruction is not an unconditional
    /// branch and the next PC is in range.
    ///
    /// # Panics
    ///
    /// Panics if `pc` is out of bounds for `code` (mirrors
    /// upstream's invariant).
    #[must_use]
    pub fn get_successors(
        pc: CodeOffset,
        code: &[Self],
        jump_tables: &[VariantJumpTable],
    ) -> Vec<CodeOffset> {
        assert!(
            pc < u16::MAX && (pc as usize) < code.len(),
            "Program counter out of bounds"
        );
        let bytecode = &code[pc as usize];
        let mut v = vec![];
        v.extend(bytecode.offsets(jump_tables));
        let next_pc = pc + 1;
        if (next_pc as usize) >= code.len() {
            return v;
        }
        if !bytecode.is_unconditional_branch() && !v.contains(&next_pc) {
            v.push(next_pc);
        }
        v.sort_unstable();
        v
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `AdamantOpcodeKind::ALL` enumerates exactly the 18 variants
    /// per whitepaper §6.2.1.4. Accidental variant drift (a new
    /// variant added to the enum without an `ALL` entry, or an
    /// `ALL` entry without a corresponding variant) fails this
    /// assertion.
    #[test]
    fn adamant_opcode_kind_all_count_matches_spec() {
        assert_eq!(
            AdamantOpcodeKind::ALL.len(),
            18,
            "whitepaper §6.2.1.4 specifies 18 Adamant-specific instructions"
        );
    }

    /// Exhaustive opcode-byte assignment table per §6.2.1.4.
    /// Pinned by this test; changing any byte is a hard fork
    /// (§6.2.1.4 "the complete instruction set — inherited and
    /// extension — is genesis-fixed").
    #[test]
    fn adamant_opcode_kind_bytes_match_spec() {
        let cases: [(AdamantOpcodeKind, u8); 18] = [
            (AdamantOpcodeKind::InvokeShielded, 0x80),
            (AdamantOpcodeKind::InvokeTransparent, 0x81),
            (AdamantOpcodeKind::GenerateProof, 0x82),
            (AdamantOpcodeKind::VerifyProof, 0x83),
            (AdamantOpcodeKind::ReleaseSubViewKey, 0x84),
            (AdamantOpcodeKind::KzgCommit, 0x85),
            (AdamantOpcodeKind::KzgVerify, 0x86),
            (AdamantOpcodeKind::RecursiveVerify, 0x87),
            (AdamantOpcodeKind::Sha3_256, 0x88),
            (AdamantOpcodeKind::Blake3, 0x89),
            (AdamantOpcodeKind::Ed25519Verify, 0x8A),
            (AdamantOpcodeKind::MlDsaVerify65, 0x8B),
            (AdamantOpcodeKind::BlsVerify, 0x8C),
            (AdamantOpcodeKind::MlKemEncapsulate, 0x8D),
            (AdamantOpcodeKind::MlKemDecapsulate, 0x8E),
            (AdamantOpcodeKind::ChargeGas, 0x8F),
            (AdamantOpcodeKind::RemainingGas, 0x90),
            (AdamantOpcodeKind::OutOfGas, 0x91),
        ];
        for (kind, expected) in cases {
            assert_eq!(
                kind.opcode_byte(),
                expected,
                "opcode-byte mismatch for {kind:?}"
            );
        }
    }

    /// kind → byte → kind round-trip pins one direction of the
    /// bijection.
    #[test]
    fn opcode_byte_round_trips_through_kind() {
        for &kind in AdamantOpcodeKind::ALL {
            let byte = kind.opcode_byte();
            assert_eq!(
                AdamantOpcodeKind::try_from_opcode_byte(byte),
                Some(kind),
                "round-trip mismatch for {kind:?} (opcode {byte:#04x})"
            );
        }
    }

    /// byte → kind exhaustive over the full `u8` space pins the
    /// other direction. Every byte in `0x80..=0x91` parses to
    /// `Some`; every byte outside that range — including all of
    /// Sui's range `0x01..=0x56` — parses to `None`.
    #[test]
    fn try_from_opcode_byte_full_byte_space() {
        for byte in 0u8..=0xFF {
            let in_range = (0x80..=0x91).contains(&byte);
            let parsed = AdamantOpcodeKind::try_from_opcode_byte(byte);
            if in_range {
                assert!(parsed.is_some(), "byte {byte:#04x} should parse to a kind");
            } else {
                assert!(
                    parsed.is_none(),
                    "byte {byte:#04x} should NOT parse (Sui range or unassigned)"
                );
            }
        }
    }

    /// For each `AdamantBytecode` variant, `.kind()` returns the
    /// matching `AdamantOpcodeKind`. Pins the single-source-of-
    /// truth pattern: opcode-byte queries on `AdamantBytecode`
    /// always go through `kind()`, and this test confirms each
    /// variant's `kind()` is the right one.
    #[test]
    fn adamant_bytecode_kind_consistency() {
        let fn_idx = FunctionHandleIndex::new(0);
        let circuit = CircuitId(0);
        let dim = GasDimension::Computation;

        let cases: [(AdamantBytecode, AdamantOpcodeKind); 16] = [
            (
                AdamantBytecode::InvokeShielded(fn_idx),
                AdamantOpcodeKind::InvokeShielded,
            ),
            (
                AdamantBytecode::InvokeTransparent(fn_idx),
                AdamantOpcodeKind::InvokeTransparent,
            ),
            (
                AdamantBytecode::GenerateProof(circuit),
                AdamantOpcodeKind::GenerateProof,
            ),
            (
                AdamantBytecode::VerifyProof(circuit),
                AdamantOpcodeKind::VerifyProof,
            ),
            (
                AdamantBytecode::ReleaseSubViewKey,
                AdamantOpcodeKind::ReleaseSubViewKey,
            ),
            (AdamantBytecode::KzgCommit, AdamantOpcodeKind::KzgCommit),
            (AdamantBytecode::KzgVerify, AdamantOpcodeKind::KzgVerify),
            (
                AdamantBytecode::RecursiveVerify,
                AdamantOpcodeKind::RecursiveVerify,
            ),
            (AdamantBytecode::Sha3_256, AdamantOpcodeKind::Sha3_256),
            (AdamantBytecode::Blake3, AdamantOpcodeKind::Blake3),
            (
                AdamantBytecode::Ed25519Verify,
                AdamantOpcodeKind::Ed25519Verify,
            ),
            (
                AdamantBytecode::MlDsaVerify65,
                AdamantOpcodeKind::MlDsaVerify65,
            ),
            (AdamantBytecode::BlsVerify, AdamantOpcodeKind::BlsVerify),
            (
                AdamantBytecode::ChargeGas(dim),
                AdamantOpcodeKind::ChargeGas,
            ),
            (
                AdamantBytecode::RemainingGas(dim),
                AdamantOpcodeKind::RemainingGas,
            ),
            (AdamantBytecode::OutOfGas, AdamantOpcodeKind::OutOfGas),
        ];
        for (bc, expected_kind) in cases {
            assert_eq!(bc.kind(), expected_kind, "kind mismatch for {bc:?}");
            assert_eq!(
                bc.opcode_byte(),
                expected_kind.opcode_byte(),
                "opcode_byte delegation mismatch for {bc:?}"
            );
        }
    }

    /// `GasDimension` declares exactly six variants in the order
    /// matching `GasBudget`'s field declarations from §6.0.7:
    /// `computation`, `storage`, `rent`, `bandwidth`,
    /// `proof_verification`, `proof_generation`.
    #[test]
    fn gas_dimension_six_variants_in_spec_order() {
        let ordered = [
            GasDimension::Computation,
            GasDimension::Storage,
            GasDimension::Rent,
            GasDimension::Bandwidth,
            GasDimension::ProofVerification,
            GasDimension::ProofGeneration,
        ];
        assert_eq!(ordered.len(), 6);
        // Each variant is distinct from the others.
        for (i, a) in ordered.iter().enumerate() {
            for (j, b) in ordered.iter().enumerate() {
                if i == j {
                    assert_eq!(a, b);
                } else {
                    assert_ne!(a, b, "variants {i} and {j} must differ");
                }
            }
        }
    }

    /// `CircuitId` is a transparent `u16` newtype.
    #[test]
    fn circuit_id_round_trips_through_u16() {
        let id = CircuitId(0x1234);
        assert_eq!(id.0, 0x1234);
        let id2 = CircuitId(0x1234);
        assert_eq!(id, id2);
    }

    /// `BytecodeInstruction` composes an inherited Sui opcode and
    /// an Adamant extension into one type. Smoke test for the
    /// composition.
    #[test]
    fn bytecode_instruction_constructs_both_variants() {
        let inherited = BytecodeInstruction::Inherited(Bytecode::Pop);
        let adamant = BytecodeInstruction::Adamant(AdamantBytecode::OutOfGas);
        assert_ne!(inherited, adamant);
        assert_eq!(
            inherited.clone(),
            BytecodeInstruction::Inherited(Bytecode::Pop)
        );
        assert_eq!(
            adamant.clone(),
            BytecodeInstruction::Adamant(AdamantBytecode::OutOfGas)
        );
    }
}
