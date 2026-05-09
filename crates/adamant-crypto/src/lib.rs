//! Adamant cryptographic primitive wrappers.
//!
//! This crate is the protocol's cryptographic foundation. It provides safe,
//! audited, constant-time wrappers around the upstream libraries specified
//! in whitepaper section 3 (Cryptographic Foundation).
//!
//! # Discipline
//!
//! - No hand-rolled cryptography. Every primitive is implemented by an
//!   upstream library named in the whitepaper.
//! - No `unsafe` in this crate. The crate inherits the workspace
//!   `unsafe_code = "forbid"` lint. The threshold-encryption module
//!   (whitepaper 3.6) needs operations not exposed by `blst`'s safe
//!   API; those are wrapped in the sibling crate
//!   `adamant-crypto-blst-extra`, which is the workspace's only
//!   `unsafe`-permitting crate. See `SECURITY.md` "Adamant-authored
//!   `unsafe` surface" for the architecture and `CONTRIBUTING.md`
//!   "Unsafe-containment architecture" for the discipline rule.
//!   Upstream `unsafe` surface in transitive dependencies is also
//!   documented in `SECURITY.md`.
//! - All operations on secret material are constant-time.
//! - Every domain-separated operation references a tag from [`domain`].
//!
//! # Module map
//!
//! | Module             | Whitepaper section | Primitives                            |
//! |--------------------|--------------------|---------------------------------------|
//! | [`hash`]           | 3.3.1, 3.3.2       | SHA3-256, SHAKE-256, BLAKE3           |
//! | `hash::poseidon`   | 3.3.3              | Poseidon (zk-circuit hashing)         |
//! | [`sig_classical`]  | 3.4.1              | Ed25519                               |
//! | [`sig_pq`]         | 3.4.2              | ML-DSA-65                             |
//! | [`bls`]            | 3.4.3              | BLS12-381 signatures and pairing      |
//! | [`symmetric`]      | 3.5                | ChaCha20-Poly1305                     |
//! | [`threshold`]      | 3.6                | BLS-based threshold encryption        |
//! | [`ml_kem`]         | 3.7                | ML-KEM-768 key encapsulation          |
//! | [`zk`]             | 3.9.1              | Halo 2 zk-SNARKs                      |
//! | [`kzg`]            | 3.9.2              | KZG vector and polynomial commitments |
//! | [`domain`]         | 3.3.1              | Centralised domain-tag registry       |
//!
//! `hash::poseidon` is rendered as plain text in this map because the
//! submodule has no implementation yet; it lands when zk circuits arrive
//! (Phase 6). See [`hash`] for the rationale on the split.

pub mod bls;
pub mod domain;
pub mod hash;
pub mod kzg;
pub mod ml_kem;
pub mod sig_classical;
pub mod sig_pq;
pub mod symmetric;
pub mod threshold;
pub mod zk;
