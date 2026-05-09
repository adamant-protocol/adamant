//! Adamant privacy layer — whitepaper §7.
//!
//! Phase 6 of the implementation. This crate hosts the privacy-
//! layer types and operations: notes, stealth addresses, view
//! keys, the global note commitment tree, encrypted memos, and
//! (at later sub-arcs) shielded-execution Halo 2 circuits.
//!
//! # Phase 6 sub-arc map
//!
//! | Sub-arc | Whitepaper | Surface |
//! |---------|------------|---------|
//! | 6.0     | §3.3.3     | [`poseidon`] — Poseidon hash helper |
//! | 6.1     | §7.1       | `Note`, `NoteCommitment` (next sub-arc) |
//! | 6.2     | §7.1.2     | `Nullifier`, nullifier-key derivation |
//! | 6.3     | §7.1.3     | GNCT skeleton (append-only Merkle tree) |
//! | 6.4     | §7.2       | Stealth addresses (ML-KEM-based) |
//! | 6.5     | §7.4       | View key hierarchy + sub-view-key derivation |
//! | 6.6     | §7.6       | Encrypted memos (probabilistic per §7.0) |
//! | 6.7     | §7.3.1.1   | `EncryptedNote` |
//! | 6.8     | §7.3       | Shielded-execution validity circuit |
//! | 6.9     | §3.7.1     | Recursive proof composition |
//!
//! # Adamant-native posture
//!
//! Per CLAUDE.md §14 Adamant-native posture, this crate's
//! external dependencies are limited to the bounded ecosystem
//! (Cat B + Cat C). Specifically:
//!
//! - `adamant-crypto` — for SHA3 / BLAKE3 / HKDF / ML-KEM /
//!   Ed25519 / ML-DSA / BLS / KZG / threshold-encryption.
//! - `halo2_gadgets` — for Poseidon (§3.3.3) and (at Phase 6.8)
//!   Halo 2 circuits over Pasta curves. Currently consumed as
//!   bounded-ecosystem (Cat C-equivalent for the proving system
//!   surface); the §14.4 Decision 1 posture (C1 / C2 / C3) is
//!   pending at the Phase 6.8 plan-gate. Until then, Phase 6.0–
//!   6.7 work only consumes the Poseidon out-of-circuit primitive
//!   surface, keeping the posture decision fully reversible.
//!
//! No new external dependencies beyond the workspace's already-
//! locked set.

#![forbid(unsafe_code)]

pub mod encrypted_note;
pub mod gnct;
pub mod memo;
pub mod note;
pub mod nullifier;
pub mod poseidon;
pub mod stealth;
pub mod view_key;

pub use encrypted_note::{
    decapsulate_for_recipient, decrypt_note_for_recipient, encapsulate_for_recipient,
    encrypt_note_for_recipient, EncryptedNote, NoteDecryptError, AUTH_TAG_BYTES,
    ML_KEM_CIPHERTEXT_BYTES,
};
pub use gnct::{
    verify_membership, GlobalNoteCommitmentTree, MerklePath, MerkleRoot, TreeFull, GNCT_DEPTH,
    GNCT_MAX_LEAVES, GNCT_RECENT_ROOTS_WINDOW,
};
pub use memo::{
    decrypt_memo, encrypt_memo, EncryptedMemo, MemoDecryptError, MemoTooLarge,
    MEMO_MAX_PLAINTEXT_BYTES,
};
pub use note::{derive_note_commitment, Note, NoteCommitment, NoteMetadata, StealthAddress};
pub use nullifier::{
    derive_nullifier, derive_nullifier_key, LeafPosition, Nullifier, NullifierKey, SpendingKey,
};
pub use poseidon::{poseidon_hash, FieldBytes, POSEIDON_OUTPUT_BYTES};
pub use stealth::{
    derive_shared_scalar, derive_stealth_address, derive_view_tag, recover_stealth_spending_key,
    Address, EncapsulatedSecret, SpendingPrivateKey, SpendingPublicKey, StealthAddressIsIdentity,
    StealthSecret, ViewTag,
};
pub use view_key::{
    derive_spending_key, derive_sub_view_key, derive_sub_view_key_seed,
    derive_viewing_decapsulation_key, derive_viewing_seed, MasterSeed, SubViewKey, ViewingSeed,
    MASTER_SEED_BYTES, VIEWING_SEED_BYTES,
};
