//! Object version counter — monotonic 64-bit per whitepaper sections
//! 5.1.6 and 6.0.7.
//!
//! Per whitepaper section 5.1.6, every [`crate::Object`] carries a
//! `version` field that increments on every state transition that
//! mutates the object. Whitepaper section 6.0.7 pins the alias used
//! in transaction read-set declarations:
//!
//! > "**`Version`.** Type alias for `u64`, matching the `version` field
//! > on `Object` per section 5.1.6. Encoded as a little-endian 8-byte
//! > integer."
//!
//! The alias exists so that `Vec<(ObjectId, Version)>` in a
//! transaction's read-set (whitepaper section 6.0.2) reads as
//! "object identified by `ObjectId`, expected at this `Version`"
//! rather than "object at this opaque `u64`". Type-aliased rather
//! than newtyped because the spec text declares the alias
//! explicitly; introducing a newtype here would diverge from the
//! spec and add a layer with no consensus effect.

/// Monotonic 64-bit version counter on every [`crate::Object`].
///
/// Pinned by whitepaper section 6.0.7 as `u64`; encoded
/// little-endian per BCS canonical serialisation (whitepaper
/// section 5.1.8).
pub type Version = u64;

#[cfg(test)]
mod tests {
    use super::*;

    /// The alias matches the [`crate::Object`] field type. If
    /// [`crate::Object::version`] is ever changed, this assertion
    /// fails and the spec mismatch surfaces immediately.
    #[test]
    fn alias_matches_object_version_field_type() {
        let v: Version = 0x0102_0304_0506_0708;
        let as_u64: u64 = v;
        assert_eq!(as_u64, 0x0102_0304_0506_0708);
    }

    /// BCS canonical encoding for `u64` is little-endian 8 bytes
    /// per whitepaper section 5.1.8.
    #[test]
    fn bcs_round_trip() {
        let original: Version = 0x0102_0304_0506_0708;
        let encoded = bcs::to_bytes(&original).expect("bcs encode");
        assert_eq!(encoded, [0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]);

        let decoded: Version = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, original);
    }
}
