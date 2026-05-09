//! Minimal Sinsemilla primitives surface — only the subset
//! that ECC chips reference.
//!
//! Adamant does NOT use Sinsemilla as a hash function (it is
//! Orchard-specific; Adamant's §7.3.2 validity circuit uses
//! Poseidon per §3.3.3). However, the upstream
//! `halo2_gadgets::ecc` chips reference `sinsemilla::primitives::K`
//! (a chunk-size constant for variable-length scalar
//! multiplication's bit decomposition) as a generic parameter
//! to `LookupRangeCheckConfig`. This module surfaces just that
//! constant — not the rest of the Sinsemilla algorithm.
//!
//! If a future workstream needs the full Sinsemilla hash for
//! some non-§7.3.2 surface, a separate sub-arc can fork the
//! external `sinsemilla 0.1.0` crate. For now, the K constant
//! is sufficient.
//!
//! `K = 10` matches the external `sinsemilla 0.1.0` crate's
//! definition (`pub const K: usize = 10;` in its `lib.rs`).
//! Sourced from the same upstream tag we forked
//! `halo2_gadgets 0.3.1` against.

/// Adamant-side fork-stub of `sinsemilla::primitives` exposing
/// just the `K` chunk-size constant. See module docs for
/// rationale.
pub mod primitives {
    /// Chunk size for variable-length scalar multiplication's
    /// bit decomposition: each lookup-table chunk covers 10
    /// bits. `2^K = 1024` entries per lookup window.
    ///
    /// Forked from `sinsemilla 0.1.0`'s `pub const K: usize = 10;`
    /// (per CLAUDE.md §14.4 Decision 1 / Path C2).
    pub const K: usize = 10;
}
