//! Adamant Move value taxonomy — the canonical encoding for values
//! flowing through `CallParams.arguments` per whitepaper section
//! 6.0.7.
//!
//! Per whitepaper section 6.0.7:
//!
//! > "**`Value`.** A discriminated union covering Adamant Move's
//! > value taxonomy:
//! >
//! > ```text
//! > Value {
//! >     U8(u8),                      // BCS variant tag 0x00
//! >     U16(u16),                    // BCS variant tag 0x01
//! >     U32(u32),                    // BCS variant tag 0x02
//! >     U64(u64),                    // BCS variant tag 0x03
//! >     U128(u128),                  // BCS variant tag 0x04
//! >     U256([u8; 32]),              // BCS variant tag 0x05, big-endian
//! >     Bool(bool),                  // BCS variant tag 0x06
//! >     Address(Address),            // BCS variant tag 0x07
//! >     Vector(Vec<Value>),          // BCS variant tag 0x08
//! >     Struct(StructValue),         // BCS variant tag 0x09
//! > }
//! >
//! > StructValue {
//! >     type_id: TypeId,
//! >     fields: Vec<Value>,
//! > }
//! > ```
//! >
//! > The `Value` enum's variant set covers Adamant Move's primitive
//! > types, addresses, the polymorphic `vector<T>` constructor
//! > (encoded recursively as `Vector(Vec<Value>)`), and user-defined
//! > structs. The variant tags are fixed at genesis. Adding a new
//! > primitive type is a hard fork."
//!
//! Variant order (and therefore BCS variant tag) is consensus-
//! critical; reordering is a hard fork. Variant tags 0x00 through
//! 0x09 are pinned by whitepaper section 6.0.7.

use serde::{Deserialize, Serialize};
use serde_big_array::BigArray;

use adamant_types::{Address, TypeId};

/// `U256` byte length: 32 bytes, big-endian per whitepaper section
/// 6.0.7. The "big-endian" descriptor is the application-layer
/// interpretation of the bytes as a 256-bit integer; the wire
/// encoding is simply 32 bytes in their stored order.
pub const U256_BYTES: usize = 32;

/// Adamant Move value (whitepaper section 6.0.7).
///
/// Variant tags (BCS ULEB128) are pinned by source order:
///
/// | Variant | Tag |
/// |---------|-----|
/// | [`Value::U8`]      | `0x00` |
/// | [`Value::U16`]     | `0x01` |
/// | [`Value::U32`]     | `0x02` |
/// | [`Value::U64`]     | `0x03` |
/// | [`Value::U128`]    | `0x04` |
/// | [`Value::U256`]    | `0x05` |
/// | [`Value::Bool`]    | `0x06` |
/// | [`Value::Address`] | `0x07` |
/// | [`Value::Vector`]  | `0x08` |
/// | [`Value::Struct`]  | `0x09` |
///
/// Reordering, removing, or adding variants is a hard fork
/// (whitepaper section 6.0.6: "the transaction format is
/// genesis-fixed").
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub enum Value {
    /// 8-bit unsigned integer. BCS variant tag `0x00`.
    U8(u8),
    /// 16-bit unsigned integer. BCS variant tag `0x01`.
    U16(u16),
    /// 32-bit unsigned integer. BCS variant tag `0x02`.
    U32(u32),
    /// 64-bit unsigned integer. BCS variant tag `0x03`.
    U64(u64),
    /// 128-bit unsigned integer. BCS variant tag `0x04`.
    U128(u128),
    /// 256-bit unsigned integer, big-endian-interpreted byte array.
    /// BCS variant tag `0x05`.
    U256(#[serde(with = "BigArray")] [u8; U256_BYTES]),
    /// Boolean. BCS variant tag `0x06`.
    Bool(bool),
    /// Account address. BCS variant tag `0x07`.
    Address(Address),
    /// Recursively-encoded vector. BCS variant tag `0x08`. Vector
    /// elements are themselves [`Value`] instances; the polymorphic
    /// `vector<T>` constructor of the language is encoded by
    /// dispatching the element type at each position.
    Vector(Vec<Value>),
    /// User-defined struct. BCS variant tag `0x09`. The interior
    /// shape is [`StructValue`].
    Struct(StructValue),
}

/// User-defined struct value (whitepaper section 6.0.7).
///
/// Carries the [`TypeId`] of the struct's type definition (per
/// whitepaper section 5.1.2) and the field values in the canonical
/// declaration order specified by the type's definition. The
/// mapping from `fields` ordering to the struct's named fields is a
/// property of the type definition, not the [`Value`] encoding.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct StructValue {
    /// Identifier of the struct's type definition (whitepaper
    /// section 5.1.2).
    pub type_id: TypeId,
    /// Field values in canonical declaration order.
    pub fields: Vec<Value>,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first byte of every variant's BCS encoding is its
    /// ULEB128 variant tag, pinned by whitepaper 6.0.7. A value
    /// fitting in a single ULEB128 byte (tag < 0x80) appears as
    /// that byte. All ten variants here have tags < 0x80.
    #[test]
    fn variant_tag_bytes_match_spec() {
        let cases: [(Value, u8); 10] = [
            (Value::U8(0), 0x00),
            (Value::U16(0), 0x01),
            (Value::U32(0), 0x02),
            (Value::U64(0), 0x03),
            (Value::U128(0), 0x04),
            (Value::U256([0; U256_BYTES]), 0x05),
            (Value::Bool(false), 0x06),
            (Value::Address(Address::from_bytes([0; 32])), 0x07),
            (Value::Vector(vec![]), 0x08),
            (
                Value::Struct(StructValue {
                    type_id: TypeId::from_bytes([0; 32]),
                    fields: vec![],
                }),
                0x09,
            ),
        ];
        for (val, expected_tag) in cases {
            let encoded = bcs::to_bytes(&val).expect("bcs encode");
            assert_eq!(
                encoded[0], expected_tag,
                "variant tag mismatch for {val:?} — whitepaper §6.0.7 pins this byte"
            );
        }
    }

    /// Each variant survives a roundtrip with non-trivial payload.
    #[test]
    fn bcs_round_trip_each_variant() {
        let cases = [
            Value::U8(0xab),
            Value::U16(0xabcd),
            Value::U32(0xabcd_1234),
            Value::U64(0x0102_0304_0506_0708),
            Value::U128(0x0102_0304_0506_0708_090a_0b0c_0d0e_0f10),
            Value::U256([0xee; U256_BYTES]),
            Value::Bool(true),
            Value::Address(Address::from_bytes([0x42; 32])),
            Value::Vector(vec![Value::U64(1), Value::U64(2), Value::U64(3)]),
            Value::Struct(StructValue {
                type_id: TypeId::from_bytes([0x33; 32]),
                fields: vec![Value::Bool(true), Value::U8(7)],
            }),
        ];
        for val in cases {
            let encoded = bcs::to_bytes(&val).expect("bcs encode");
            let decoded: Value = bcs::from_bytes(&encoded).expect("bcs decode");
            assert_eq!(decoded, val);
        }
    }

    /// `Vector` is recursive: a vector of vectors of values
    /// roundtrips correctly. This pins the recursion semantics of
    /// the polymorphic `vector<T>` constructor.
    #[test]
    fn vector_recursion_round_trips() {
        let val = Value::Vector(vec![
            Value::Vector(vec![Value::U8(1), Value::U8(2)]),
            Value::Vector(vec![Value::U8(3), Value::U8(4), Value::U8(5)]),
        ]);
        let encoded = bcs::to_bytes(&val).expect("bcs encode");
        let decoded: Value = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, val);
    }

    /// `StructValue.fields` is itself a `Vec<Value>`, so a struct
    /// containing another struct round-trips correctly.
    #[test]
    fn struct_recursion_round_trips() {
        let inner = StructValue {
            type_id: TypeId::from_bytes([0x11; 32]),
            fields: vec![Value::U64(42)],
        };
        let outer = StructValue {
            type_id: TypeId::from_bytes([0x22; 32]),
            fields: vec![Value::Struct(inner.clone()), Value::Bool(false)],
        };
        let val = Value::Struct(outer.clone());
        let encoded = bcs::to_bytes(&val).expect("bcs encode");
        let decoded: Value = bcs::from_bytes(&encoded).expect("bcs decode");
        assert_eq!(decoded, val);
    }

    /// `StructValue` itself (not wrapped in `Value::Struct`) BCS-
    /// encodes as `BCS(type_id) || BCS(fields)`. Field ordering
    /// matches whitepaper section 6.0.7 declaration order.
    #[test]
    fn struct_value_bcs_field_order() {
        let s = StructValue {
            type_id: TypeId::from_bytes([0x55; 32]),
            fields: vec![Value::Bool(true)],
        };
        let encoded = bcs::to_bytes(&s).expect("bcs encode");
        // First 32 bytes: type_id; then a Vec<Value> BCS encoding.
        assert_eq!(encoded[0..32], [0x55; 32]);
        // The Vec<Value> with one Bool(true) entry is:
        // ULEB128(1) || variant tag 0x06 || true (0x01) = 0x01 0x06 0x01
        assert_eq!(&encoded[32..], &[0x01, 0x06, 0x01]);
    }
}
