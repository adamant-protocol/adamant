//! Hash-function wrappers, per whitepaper section 3.3.
//!
//! - SHA3-256 and SHAKE-256 (3.3.1) for all consensus-critical hashing.
//! - BLAKE3 (3.3.2) for non-consensus-critical performance paths.
//!
//! Poseidon (3.3.3) is split into a `poseidon` submodule under `hash`. It
//! is conceptually a hash per the whitepaper's taxonomy, but its library
//! (`halo2_gadgets`), API surface, and use sites (inside Halo 2 circuits
//! only) are entirely separate from SHA3 and BLAKE3. Co-locating them
//! would produce a confusing module once implemented. The submodule
//! file lands when zk circuits arrive (Phase 6).
