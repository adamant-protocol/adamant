//! Adamant validator configuration.
//!
//! [`AdamantVerifierConfig`] wraps **both** Sui-Move configs the
//! Adamant validator depends on:
//!
//! - [`BinaryConfig`] — used by
//!   [`CompiledModule::deserialize_with_config`] for the parse
//!   step. With `deprecate_global_storage_ops = true`, the
//!   deserializer rejects the 10 deprecated global-storage
//!   bytecode variants at *parse* time (per
//!   `vendor/move-binary-format/src/deserializer.rs:1657`); this
//!   is the actual enforcement point for whitepaper §6.2.1.6
//!   Rule 5.
//! - [`VerifierConfig`] — used by Sui's
//!   `move-bytecode-verifier` for the inherited verifier passes
//!   (type safety, reference safety, linearity, etc.). The
//!   `deprecate_global_storage_ops` flag is also set here as
//!   defense in depth — Sui's `BoundsChecker` carries a
//!   `safe_assert!` that ensures any deprecated variant slipping
//!   past the deserializer surfaces as an error at verification.
//!
//! Both flags are forced to `true` non-overridably. Future
//! configuration knobs (e.g., for Rule 6's
//! `b"adamant.allows_dynamic"` opt-in once Wave 3c lands) extend
//! this struct rather than exposing Sui's full config types to
//! callers.

use move_binary_format::binary_config::BinaryConfig;
use move_vm_config::verifier::VerifierConfig;

/// Configuration for the Adamant validator.
///
/// Wraps both [`BinaryConfig`] (consumed by the deserializer) and
/// [`VerifierConfig`] (consumed by the inherited verifier passes)
/// with consensus-critical settings locked down. The
/// `deprecate_global_storage_ops` flag is `true` in both
/// configs and cannot be overridden through the public API; this
/// is what enforces §6.2.1.6 Rule 5 (no global storage
/// instructions) at the deserialize stage where Sui's pipeline
/// actually rejects deprecated variants.
#[derive(Debug, Clone)]
pub struct AdamantVerifierConfig {
    sui_verifier_config: VerifierConfig,
    sui_binary_config: BinaryConfig,
}

impl AdamantVerifierConfig {
    /// Build an Adamant validator config with consensus-critical
    /// settings locked down.
    ///
    /// Forces `deprecate_global_storage_ops = true` in both the
    /// binary config (for the deserializer) and the verifier
    /// config (for the inherited verifier passes). This is what
    /// carries the §6.2.1.6 Rule 5 enforcement.
    ///
    /// Sets `check_no_extraneous_bytes = false` in the binary
    /// config — the metadata table is gated by this flag (Sui's
    /// deserializer rejects modules carrying a metadata table
    /// when the flag is `true`, per
    /// `vendor/move-binary-format/src/deserializer.rs:585`),
    /// and Adamant's §6.2.1.3 design requires the metadata
    /// table (for `b"adamant.mutability"` per Rule 1,
    /// `b"adamant.privacy"` per Rule 2,
    /// `b"adamant.allows_dynamic"` per Rule 6). The canonicality
    /// the flag would otherwise provide is recovered by an
    /// explicit canonical-encoding round-trip check after
    /// deserialize in [`super::verify_module`] (Step 2 of the
    /// pipeline): the parsed module is re-serialized via Sui's
    /// serializer and the output is byte-compared to the input;
    /// a mismatch surfaces as
    /// [`super::AdamantValidationError::NonCanonicalBytecode`].
    /// The two-step posture (relax Sui's flag, enforce
    /// canonicality explicitly) lets Adamant accept the
    /// metadata table while still rejecting trailing-byte
    /// smuggling and other non-canonical encodings — consistent
    /// with §6.0.6 / §6.0.7's canonical-encoding posture for
    /// transactions.
    #[must_use]
    pub fn new() -> Self {
        // Whitepaper §6.2.1.6 Rule 5 enforcement, deserializer
        // side: deprecate_global_storage_ops=true forces the
        // deserializer to reject the 10 deprecated global-storage
        // bytecode variants at parse time per
        // `vendor/move-binary-format/src/deserializer.rs:1657`.
        //
        // check_no_extraneous_bytes=false because Sui's
        // deserializer rejects metadata tables under strict
        // mode (line 585 of deserializer.rs), and Adamant's
        // §6.2.1.3 amendment relies on the metadata table to
        // store privacy and mutability annotations. See the
        // doc comment on this constructor for the canonicality
        // follow-up consideration this opens.
        let sui_binary_config = BinaryConfig::legacy_with_flags(
            /* check_no_extraneous_bytes */ false,
            /* deprecate_global_storage_ops */ true,
        );

        // Whitepaper §6.2.1.6 Rule 5 enforcement, verifier side
        // (defense in depth — the deserializer catches deprecated
        // variants first; this is the safety net via Sui's
        // BoundsChecker `safe_assert!`). Set via struct-update
        // syntax rather than field-after-default assignment so
        // Sui-Move config additions show up as build errors here
        // (forcing an explicit choice for any new field) rather
        // than being silently picked up at their upstream default.
        let sui_verifier_config = VerifierConfig {
            deprecate_global_storage_ops: true,
            ..VerifierConfig::default()
        };

        Self {
            sui_verifier_config,
            sui_binary_config,
        }
    }

    /// Return a reference to the wrapped Sui [`VerifierConfig`].
    ///
    /// Crate-internal: callers outside the validator module
    /// should not need to inspect or override the locked-down
    /// fields.
    pub(super) fn sui_verifier_config(&self) -> &VerifierConfig {
        &self.sui_verifier_config
    }

    /// Return a reference to the wrapped Sui [`BinaryConfig`].
    ///
    /// Crate-internal: callers outside the validator module
    /// should not need to inspect or override the locked-down
    /// fields.
    pub(super) fn sui_binary_config(&self) -> &BinaryConfig {
        &self.sui_binary_config
    }
}

impl Default for AdamantVerifierConfig {
    fn default() -> Self {
        Self::new()
    }
}
