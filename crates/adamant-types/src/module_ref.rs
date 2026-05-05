//! Module reference — newtype over [`crate::ObjectId`] for
//! `CallParams.target_module` per whitepaper sections 6.0.2 and
//! 6.0.7.
//!
//! Per whitepaper section 6.4.1, modules are first-class on-chain
//! objects: "Module deployment is a transaction whose effect is to
//! create a new `Module` object on the chain." Per whitepaper
//! section 6.0.7:
//!
//! > "**`ModuleRef`.** A newtype wrapping `ObjectId`:
//! >
//! > ```text
//! > ModuleRef(ObjectId)
//! > ```
//! >
//! > per section 6.4.1's framing of modules as first-class objects.
//! > Encoded as the wrapped `ObjectId` (32 bytes, no additional
//! > discriminator)."
//!
//! The newtype exists so that call-site signatures distinguish "an
//! `ObjectId` referring to a module" from "an `ObjectId` referring
//! to any other object kind", without changing the canonical
//! encoding.

use serde::{Deserialize, Serialize};

use crate::object_id::ObjectId;

/// Reference to a deployed module (whitepaper section 6.0.7).
///
/// Encodes as the wrapped 32-byte [`ObjectId`] with no additional
/// discriminator — a tuple struct with a single field is BCS-
/// encoded transparently as the inner field.
#[derive(Clone, Copy, Eq, PartialEq, Hash, Debug, Serialize, Deserialize)]
pub struct ModuleRef(pub ObjectId);

impl ModuleRef {
    /// Borrow the underlying [`ObjectId`].
    #[must_use]
    pub const fn as_object_id(&self) -> &ObjectId {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixed_object_id() -> ObjectId {
        ObjectId::from_bytes([
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e,
            0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
            0x1d, 0x1e, 0x1f, 0x20,
        ])
    }

    #[test]
    fn construct_and_borrow() {
        let oid = fixed_object_id();
        let m = ModuleRef(oid);
        assert_eq!(m.as_object_id(), &oid);
    }

    /// BCS encoding of a tuple struct with one field is the inner
    /// field's encoding directly — 32 bytes for an [`ObjectId`],
    /// with no discriminator. Whitepaper section 6.0.7 pins this.
    #[test]
    fn bcs_round_trip_is_inner_object_id_bytes() {
        let oid = fixed_object_id();
        let m = ModuleRef(oid);
        let encoded = bcs::to_bytes(&m).expect("bcs encode");
        assert_eq!(encoded.len(), 32);
        assert_eq!(encoded, oid.as_bytes());

        let decoded: ModuleRef = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, m);
    }
}
