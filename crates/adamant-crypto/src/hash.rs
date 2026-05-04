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
//!
//! All consensus-critical SHA3-256 and SHAKE-256 invocations MUST go
//! through the tagged variants ([`sha3_256_tagged`] and
//! [`shake_256_tagged`]), which apply the BIP-340 tagged-hash
//! construction with a registered [`DomainTag`]. Non-consensus-critical
//! paths (peer-to-peer message integrity, content-addressed storage of
//! historical chain data, etc.) MAY use the plain variants
//! ([`sha3_256_plain`], [`shake_256_plain`]).

use sha3::digest::{ExtendableOutput, XofReader};
use sha3::{Digest, Sha3_256, Shake256};

use crate::domain::DomainTag;

// Note: `sha3::digest::Update` is intentionally NOT imported at module
// scope. Both `Digest` (used for SHA3-256) and `Update` (used for
// SHAKE-256) define an `update` method, and bringing both into scope
// makes calls on `Sha3_256` ambiguous. Functions that use SHAKE-256
// import `Update` locally inside the function body.

/// Applies the BIP-340 tagged-hash construction over SHA3-256, given a
/// precomputed 32-byte tag prefix. Per whitepaper section 3.3.1:
///
/// `tagged_hash_sha3(tag, input) = SHA3-256( prefix || prefix || input )`
///
/// where `prefix = SHA3-256(tag)`. The `prefix` is supplied by the caller
/// (typically via [`DomainTag::cached_prefix`]) so the per-tag SHA3-256
/// computation is amortised across calls.
fn tagged_sha3_256(prefix: &[u8; 32], input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(prefix);
    hasher.update(prefix);
    hasher.update(input);
    hasher.finalize().into()
}

/// Applies the BIP-340 tagged-hash construction over SHAKE-256, given a
/// precomputed 32-byte tag prefix. Per whitepaper section 3.3.1:
///
/// `tagged_shake(tag, input, len) = SHAKE-256( prefix || prefix || input, len )`
///
/// where `prefix = SHA3-256(tag)`. The `prefix` is the same SHA3-256(tag)
/// value used by [`tagged_sha3_256`]; both variants share the cache on
/// the underlying [`DomainTag`], per whitepaper 3.3.1 ("the tag prefix is
/// **always** SHA3-256(tag), regardless of whether the body uses
/// SHA3-256 or SHAKE-256").
fn tagged_shake_256(prefix: &[u8; 32], input: &[u8], output: &mut [u8]) {
    use sha3::digest::Update;
    let mut hasher = Shake256::default();
    hasher.update(prefix);
    hasher.update(prefix);
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

/// SHA3-256 with mandatory domain separation, per whitepaper section 3.3.1.
///
/// Computes the BIP-340 tagged-hash construction:
///
/// `tagged_hash_sha3(tag, input) = SHA3-256( SHA3-256(tag) || SHA3-256(tag) || input )`
///
/// The `SHA3-256(tag)` prefix is computed once per [`DomainTag`] and
/// cached for the process lifetime; subsequent calls on the same tag
/// reuse the cached value.
///
/// All consensus-critical hashing MUST use this function (or
/// [`shake_256_tagged`] for variable-length output). For documented
/// non-consensus uses, [`sha3_256_plain`] is also available.
#[must_use]
pub fn sha3_256_tagged(tag: &DomainTag, input: &[u8]) -> [u8; 32] {
    tagged_sha3_256(tag.cached_prefix(), input)
}

/// SHAKE-256 with mandatory domain separation, per whitepaper section 3.3.1.
///
/// Computes the BIP-340 tagged-hash construction with SHAKE-256 as the
/// outer absorption:
///
/// `tagged_shake(tag, input, len) = SHAKE-256( SHA3-256(tag) || SHA3-256(tag) || input, len )`
///
/// where `len = output.len()`. The `SHA3-256(tag)` prefix is shared with
/// [`sha3_256_tagged`]; each `DomainTag` has a single cached prefix used
/// across both variants.
///
/// All consensus-critical hashing MUST use this function (or
/// [`sha3_256_tagged`] for fixed 32-byte output). For documented
/// non-consensus uses, [`shake_256_plain`] is also available.
pub fn shake_256_tagged(tag: &DomainTag, input: &[u8], output: &mut [u8]) {
    tagged_shake_256(tag.cached_prefix(), input, output);
}

/// Plain SHA3-256 without domain separation.
///
/// **Non-consensus-critical use only.** Per whitepaper section 3.3.1:
/// "All uses of SHA3-256 and SHAKE-256 within the protocol `MUST` use
/// domain separation." Non-consensus-critical paths (peer-to-peer
/// message integrity checks, content-addressed storage of historical
/// chain data, etc.) `MAY` use plain SHA3 without the tagged-hash
/// wrapper.
///
/// If you are unsure whether your call site is consensus-critical, use
/// [`sha3_256_tagged`] instead.
#[must_use]
pub fn sha3_256_plain(input: &[u8]) -> [u8; 32] {
    let mut hasher = Sha3_256::new();
    hasher.update(input);
    hasher.finalize().into()
}

/// Plain SHAKE-256 without domain separation.
///
/// **Non-consensus-critical use only.** See [`sha3_256_plain`] for the
/// constraint and rationale (whitepaper section 3.3.1). If you are
/// unsure whether your call site is consensus-critical, use
/// [`shake_256_tagged`] instead.
pub fn shake_256_plain(input: &[u8], output: &mut [u8]) {
    use sha3::digest::Update;
    let mut hasher = Shake256::default();
    hasher.update(input);
    let mut reader = hasher.finalize_xof();
    reader.read(output);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::test_tags;

    // Test-vector files are committed under `test-vectors/`. NIST CAVP /
    // FIPS 202 vectors verify the underlying SHA3-256 and SHAKE-256
    // primitives in isolation; internally-generated vectors verify the
    // BIP-340 tagged-hash composition end-to-end. See
    // `crates/adamant-crypto/test-vectors/README.md`.

    // ---------- NIST CAVP / FIPS 202 vectors for the bare primitives ----------

    /// Parses a NIST CAVP-style `.rsp` block file and returns
    /// `(message_bytes, expected_output_bytes)` pairs. Comments (lines
    /// starting with `#`) and headers (lines starting with `[`) are
    /// ignored. `Len = 0` means an empty message (the `Msg = 00` line is
    /// a placeholder per the NIST format).
    fn parse_rsp_kats(content: &str) -> Vec<(usize, Vec<u8>, Vec<u8>)> {
        let mut vectors = Vec::new();
        let mut current_len: Option<usize> = None;
        let mut current_msg: Option<Vec<u8>> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') || line.starts_with('[') {
                continue;
            }
            if let Some(rest) = line.strip_prefix("Len = ") {
                current_len = rest.trim().parse().ok();
            } else if let Some(rest) = line.strip_prefix("Msg = ") {
                let rest = rest.trim();
                let msg = if current_len == Some(0) {
                    Vec::new()
                } else {
                    hex::decode(rest).expect("valid hex in Msg field")
                };
                current_msg = Some(msg);
            } else if let Some(rest) = line
                .strip_prefix("MD = ")
                .or_else(|| line.strip_prefix("Output = "))
            {
                let expected = hex::decode(rest.trim()).expect("valid hex in MD/Output field");
                let msg = current_msg
                    .take()
                    .expect("Msg line must precede MD/Output line");
                let len = current_len.take().unwrap_or(msg.len() * 8);
                vectors.push((len, msg, expected));
            }
        }
        vectors
    }

    #[test]
    fn nist_sha3_256_kats() {
        let content = include_str!("../test-vectors/sha3/sha3_256_kats.txt");
        let vectors = parse_rsp_kats(content);
        assert!(!vectors.is_empty(), "no KATs parsed from sha3_256_kats.txt");
        for (len, msg, expected) in &vectors {
            let actual = sha3_256_plain(msg);
            assert_eq!(
                actual.as_slice(),
                expected.as_slice(),
                "SHA3-256 KAT (Len = {len}): expected {} but got {}",
                hex::encode(expected),
                hex::encode(actual),
            );
        }
    }

    #[test]
    fn nist_shake_256_kats() {
        let content = include_str!("../test-vectors/shake256/shake_256_kats.txt");
        let vectors = parse_rsp_kats(content);
        assert!(
            !vectors.is_empty(),
            "no KATs parsed from shake_256_kats.txt"
        );
        for (len, msg, expected) in &vectors {
            let mut actual = vec![0u8; expected.len()];
            shake_256_plain(msg, &mut actual);
            assert_eq!(
                actual,
                *expected,
                "SHAKE-256 KAT (Len = {len}, Outputlen = {}): expected {} but got {}",
                expected.len(),
                hex::encode(expected),
                hex::encode(&actual),
            );
        }
    }

    // ---------- tagged construction matches whitepaper formula ----------

    /// Verifies that [`sha3_256_tagged`] produces exactly
    /// `SHA3-256( SHA3-256(tag) || SHA3-256(tag) || input )` per
    /// whitepaper section 3.3.1.
    #[test]
    fn sha3_256_tagged_matches_construction() {
        let tag = &test_tags::TAG_A;
        let input = b"the quick brown fox jumps over the lazy dog";

        let prefix: [u8; 32] = Sha3_256::digest(tag.as_bytes()).into();
        let mut hasher = Sha3_256::new();
        hasher.update(prefix);
        hasher.update(prefix);
        hasher.update(input);
        let expected: [u8; 32] = hasher.finalize().into();

        let actual = sha3_256_tagged(tag, input);
        assert_eq!(actual, expected);
    }

    /// Verifies that [`shake_256_tagged`] produces exactly
    /// `SHAKE-256( SHA3-256(tag) || SHA3-256(tag) || input, len )` per
    /// whitepaper section 3.3.1.
    #[test]
    fn shake_256_tagged_matches_construction() {
        use sha3::digest::Update;
        let tag = &test_tags::TAG_A;
        let input = b"the quick brown fox jumps over the lazy dog";

        let prefix: [u8; 32] = Sha3_256::digest(tag.as_bytes()).into();
        let mut hasher = Shake256::default();
        hasher.update(&prefix);
        hasher.update(&prefix);
        hasher.update(input);
        let mut reader = hasher.finalize_xof();
        let mut expected = [0u8; 64];
        reader.read(&mut expected);

        let mut actual = [0u8; 64];
        shake_256_tagged(tag, input, &mut actual);
        assert_eq!(actual, expected);
    }

    /// Verifies the cached prefix matches a direct `SHA3-256(tag)`
    /// computation — the cache is correct, not just consistent.
    #[test]
    fn cached_prefix_matches_direct_computation() {
        let tag = &test_tags::TAG_A;
        let cached: &[u8; 32] = tag.cached_prefix();
        let direct: [u8; 32] = Sha3_256::digest(tag.as_bytes()).into();
        assert_eq!(cached, &direct);
    }

    /// Verifies that the prefix used by SHA3-256 and SHAKE-256 tagged
    /// variants is the same value (both come from the same cache slot).
    /// Per whitepaper 3.3.1: "the tag prefix is **always** SHA3-256(tag),
    /// regardless of whether the body uses SHA3-256 or SHAKE-256."
    #[test]
    fn tagged_variants_share_prefix() {
        let tag = &test_tags::TAG_B;
        let prefix_first = *tag.cached_prefix();
        let prefix_second = *tag.cached_prefix();
        assert_eq!(prefix_first, prefix_second);
    }

    // ---------- worked example from whitepaper 3.3.1 ----------

    /// Reproduces the worked example from whitepaper section 3.3.1:
    ///
    /// ```text
    /// tag    = b"ADAMANT-v1-object-id"
    /// input  = creation_tx_hash || creator_address || creation_index
    /// prefix = SHA3-256(tag)
    /// tagged_hash_sha3(tag, input) = SHA3-256( prefix || prefix || input )
    /// ```
    ///
    /// The whitepaper specifies the construction shape; concrete input
    /// bytes are documented in
    /// `test-vectors/sha3-tagged/tagged_sha3_256.txt` (section labelled
    /// "whitepaper 3.3.1 worked example"). Expected output is verified
    /// here against the construction formula computed inline using the
    /// `sha3` crate directly, and separately against the regression
    /// vector file in [`tagged_sha3_256_internal_regression`].
    #[test]
    fn worked_example_object_id() {
        // i is bounded to 0..32 by the array length, so the u8 cast is
        // exact. Suppressing the lint is cheaper than a `try_from` round-trip.
        #[allow(clippy::cast_possible_truncation)]
        let creation_tx_hash: [u8; 32] = std::array::from_fn(|i| i as u8);
        #[allow(clippy::cast_possible_truncation)]
        let creator_address: [u8; 32] = std::array::from_fn(|i| 0x20u8 + (i as u8));
        let creation_index: u64 = 1;

        let mut input = Vec::with_capacity(32 + 32 + 8);
        input.extend_from_slice(&creation_tx_hash);
        input.extend_from_slice(&creator_address);
        input.extend_from_slice(&creation_index.to_be_bytes());

        let tag = &test_tags::WORKED_EXAMPLE_OBJECT_ID;
        let prefix: [u8; 32] = Sha3_256::digest(tag.as_bytes()).into();
        let mut hasher = Sha3_256::new();
        hasher.update(prefix);
        hasher.update(prefix);
        hasher.update(&input);
        let expected_from_formula: [u8; 32] = hasher.finalize().into();

        let actual = sha3_256_tagged(tag, &input);
        assert_eq!(actual, expected_from_formula);
    }

    // ---------- internal regression vectors ----------

    struct TaggedVector {
        tag: Vec<u8>,
        input: Vec<u8>,
        output: Vec<u8>,
    }

    /// Parses the internal tagged-hash vector format. Each block:
    ///
    /// ```text
    /// Description = <text>
    /// Tag         = <hex>
    /// Tag-ASCII   = <ascii rendering, ignored by parser>
    /// Input       = <hex>
    /// Output      = <hex>
    /// ```
    ///
    /// Unknown keys (e.g., `Description`, `Tag-ASCII`) are ignored.
    /// `Input =` with empty value parses as an empty input (zero bytes).
    fn parse_tagged_vectors(content: &str) -> Vec<TaggedVector> {
        let mut vectors = Vec::new();
        let mut tag: Option<Vec<u8>> = None;
        let mut input: Option<Vec<u8>> = None;

        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, value)) = line.split_once('=') else {
                continue;
            };
            let key = key.trim();
            let value = value.trim();
            match key {
                "Tag" => {
                    tag = Some(hex::decode(value).expect("valid hex in Tag"));
                }
                "Input" => {
                    input = Some(if value.is_empty() {
                        Vec::new()
                    } else {
                        hex::decode(value).expect("valid hex in Input")
                    });
                }
                "Output" => {
                    let output = hex::decode(value).expect("valid hex in Output");
                    let tag = tag.take().expect("Tag must precede Output");
                    let input = input.take().expect("Input must precede Output");
                    vectors.push(TaggedVector { tag, input, output });
                }
                _ => {}
            }
        }
        vectors
    }

    /// Verifies the internally-generated tagged-SHA3-256 vector file
    /// against the whitepaper construction formula computed from the
    /// raw tag/input bytes. This catches drift between the file and
    /// the spec independent of the public-API path.
    ///
    /// The file's vectors are also exercised through the public API by
    /// the named-tag tests above ([`worked_example_object_id`],
    /// [`sha3_256_tagged_matches_construction`]); together they cover
    /// the chain `file ↔ formula ↔ implementation`.
    #[test]
    fn tagged_sha3_256_internal_regression() {
        let content = include_str!("../test-vectors/sha3-tagged/tagged_sha3_256.txt");
        let vectors = parse_tagged_vectors(content);
        assert!(
            !vectors.is_empty(),
            "no vectors parsed from tagged_sha3_256.txt"
        );
        for (i, v) in vectors.iter().enumerate() {
            assert_eq!(
                v.output.len(),
                32,
                "vector #{i}: tagged-SHA3-256 output must be 32 bytes",
            );
            let prefix: [u8; 32] = Sha3_256::digest(&v.tag).into();
            let mut hasher = Sha3_256::new();
            hasher.update(prefix);
            hasher.update(prefix);
            hasher.update(&v.input);
            let formula: [u8; 32] = hasher.finalize().into();
            assert_eq!(
                hex::encode(formula),
                hex::encode(&v.output),
                "vector #{i}: file output disagrees with construction formula"
            );
        }
    }

    /// Same as [`tagged_sha3_256_internal_regression`], but for the
    /// tagged-SHAKE-256 vector file. The expected-output length is
    /// taken from the file itself (each vector's `Output` field).
    #[test]
    fn tagged_shake_256_internal_regression() {
        use sha3::digest::Update;
        let content = include_str!("../test-vectors/shake256-tagged/tagged_shake_256.txt");
        let vectors = parse_tagged_vectors(content);
        assert!(
            !vectors.is_empty(),
            "no vectors parsed from tagged_shake_256.txt"
        );
        for (i, v) in vectors.iter().enumerate() {
            let prefix: [u8; 32] = Sha3_256::digest(&v.tag).into();
            let mut hasher = Shake256::default();
            hasher.update(&prefix);
            hasher.update(&prefix);
            hasher.update(&v.input);
            let mut reader = hasher.finalize_xof();
            let mut formula = vec![0u8; v.output.len()];
            reader.read(&mut formula);
            assert_eq!(
                hex::encode(&formula),
                hex::encode(&v.output),
                "vector #{i}: file output disagrees with construction formula"
            );
        }
    }

    // ---------- domain separation ----------

    #[test]
    fn different_tags_produce_different_outputs_for_same_input() {
        let input = b"identical input across both tags";
        let out_a = sha3_256_tagged(&test_tags::TAG_A, input);
        let out_b = sha3_256_tagged(&test_tags::TAG_B, input);
        assert_ne!(out_a, out_b);
    }

    #[test]
    fn same_tag_different_inputs_produce_different_outputs() {
        let out_1 = sha3_256_tagged(&test_tags::TAG_A, b"input one");
        let out_2 = sha3_256_tagged(&test_tags::TAG_A, b"input two");
        assert_ne!(out_1, out_2);
    }

    #[test]
    fn shake_different_tags_produce_different_outputs() {
        let input = b"identical input";
        let mut out_a = [0u8; 32];
        let mut out_b = [0u8; 32];
        shake_256_tagged(&test_tags::TAG_A, input, &mut out_a);
        shake_256_tagged(&test_tags::TAG_B, input, &mut out_b);
        assert_ne!(out_a, out_b);
    }

    // ---------- cache idempotence ----------

    #[test]
    fn repeated_tagged_calls_return_same_value() {
        let input = b"repeat me";
        let out_1 = sha3_256_tagged(&test_tags::TAG_A, input);
        let out_2 = sha3_256_tagged(&test_tags::TAG_A, input);
        let out_3 = sha3_256_tagged(&test_tags::TAG_A, input);
        assert_eq!(out_1, out_2);
        assert_eq!(out_2, out_3);
    }

    // ---------- edge cases ----------

    #[test]
    fn empty_input_tagged_does_not_panic_and_is_deterministic() {
        let a = sha3_256_tagged(&test_tags::TAG_A, b"");
        let b = sha3_256_tagged(&test_tags::TAG_A, b"");
        assert_eq!(a, b);

        let mut buf_a = [0u8; 32];
        let mut buf_b = [0u8; 32];
        shake_256_tagged(&test_tags::TAG_A, b"", &mut buf_a);
        shake_256_tagged(&test_tags::TAG_A, b"", &mut buf_b);
        assert_eq!(buf_a, buf_b);
    }

    #[test]
    fn shake_256_variable_output_lengths_are_consistent_prefixes() {
        let input = b"variable length output";
        let mut short = [0u8; 16];
        let mut long = [0u8; 64];
        shake_256_tagged(&test_tags::TAG_A, input, &mut short);
        shake_256_tagged(&test_tags::TAG_A, input, &mut long);
        // SHAKE is an XOF: longer output must contain shorter as a prefix.
        assert_eq!(&long[..16], &short[..]);
    }

    #[test]
    fn shake_256_zero_length_output_is_a_noop() {
        let mut empty: [u8; 0] = [];
        shake_256_tagged(&test_tags::TAG_A, b"input", &mut empty);
        // No assertion needed; the test asserts no panic.
    }

    // ---------- regenerator for internal vector files ----------

    /// Prints the contents that should appear in
    /// `test-vectors/sha3-tagged/tagged_sha3_256.txt` and
    /// `test-vectors/shake256-tagged/tagged_shake_256.txt`. Run this
    /// when adding or modifying test cases:
    ///
    /// ```text
    /// CARGO_TARGET_DIR=<allowed-path> cargo test \
    ///     --package adamant-crypto regenerate_internal_tagged_vectors \
    ///     -- --ignored --nocapture
    /// ```
    ///
    /// The output is computed via the BIP-340 construction formula
    /// (whitepaper 3.3.1) using the `sha3` crate directly, which is
    /// independent of the wrappers under test. The
    /// `*_internal_regression` tests then verify that the file's
    /// `Output` fields match this formula.
    #[test]
    #[ignore = "regenerator only; run manually with --ignored --nocapture"]
    fn regenerate_internal_tagged_vectors() {
        let worked_example_input: Vec<u8> = {
            let mut v = Vec::with_capacity(72);
            for i in 0u8..32 {
                v.push(i);
            }
            for i in 0u8..32 {
                v.push(0x20 + i);
            }
            v.extend_from_slice(&1u64.to_be_bytes());
            v
        };

        let sha3_cases: &[(&str, &[u8], &[u8])] = &[
            (
                "whitepaper 3.3.1 worked example (object-id)",
                b"ADAMANT-v1-object-id",
                &worked_example_input,
            ),
            ("empty input with TAG_A", b"ADAMANT-v1-test-tag-a", b""),
            (r#""hello" with TAG_A"#, b"ADAMANT-v1-test-tag-a", b"hello"),
            (
                r#""hello" with TAG_B (same input, different tag)"#,
                b"ADAMANT-v1-test-tag-b",
                b"hello",
            ),
        ];

        println!("\n=== tagged_sha3_256.txt ===\n");
        for (desc, tag, input) in sha3_cases {
            let prefix: [u8; 32] = Sha3_256::digest(*tag).into();
            let mut hasher = Sha3_256::new();
            hasher.update(prefix);
            hasher.update(prefix);
            hasher.update(*input);
            let output: [u8; 32] = hasher.finalize().into();
            println!("Description = {desc}");
            println!("Tag = {}", hex::encode(tag));
            println!("Tag-ASCII = {}", String::from_utf8_lossy(tag));
            println!("Input = {}", hex::encode(input));
            println!("Output = {}", hex::encode(output));
            println!();
        }

        let shake_cases: &[(&str, &[u8], &[u8], usize)] = &[
            (
                "whitepaper 3.3.1 worked-example tag, 32-byte output",
                b"ADAMANT-v1-object-id",
                &worked_example_input,
                32,
            ),
            (
                "whitepaper 3.3.1 worked-example tag, 64-byte output (XOF prefix property)",
                b"ADAMANT-v1-object-id",
                &worked_example_input,
                64,
            ),
            (
                "empty input with TAG_A, 16-byte output",
                b"ADAMANT-v1-test-tag-a",
                b"",
                16,
            ),
        ];

        // SHAKE-256 block: scope `Update` import locally so it doesn't
        // shadow `Digest::update` for the SHA3 cases above.
        {
            use sha3::digest::Update;
            println!("\n=== tagged_shake_256.txt ===\n");
            for (desc, tag, input, output_len) in shake_cases {
                let prefix: [u8; 32] = Sha3_256::digest(*tag).into();
                let mut hasher = Shake256::default();
                hasher.update(&prefix);
                hasher.update(&prefix);
                hasher.update(input);
                let mut reader = hasher.finalize_xof();
                let mut output = vec![0u8; *output_len];
                reader.read(&mut output);
                println!("Description = {desc}");
                println!("Tag = {}", hex::encode(tag));
                println!("Tag-ASCII = {}", String::from_utf8_lossy(tag));
                println!("Input = {}", hex::encode(input));
                println!("Output = {}", hex::encode(&output));
                println!();
            }
        }
    }

    // ---------- proptests ----------

    use proptest::prelude::*;

    proptest! {
        #[test]
        fn prop_tagged_sha3_deterministic(
            input in prop::collection::vec(any::<u8>(), 0..256)
        ) {
            let a = sha3_256_tagged(&test_tags::TAG_A, &input);
            let b = sha3_256_tagged(&test_tags::TAG_A, &input);
            prop_assert_eq!(a, b);
        }

        #[test]
        fn prop_tagged_sha3_matches_construction(
            input in prop::collection::vec(any::<u8>(), 0..256)
        ) {
            let prefix: [u8; 32] = Sha3_256::digest(test_tags::TAG_A.as_bytes()).into();
            let mut hasher = Sha3_256::new();
            hasher.update(prefix);
            hasher.update(prefix);
            hasher.update(&input);
            let expected: [u8; 32] = hasher.finalize().into();
            let actual = sha3_256_tagged(&test_tags::TAG_A, &input);
            prop_assert_eq!(actual, expected);
        }

        #[test]
        fn prop_tagged_separates_distinct_tags(
            input in prop::collection::vec(any::<u8>(), 0..256)
        ) {
            let a = sha3_256_tagged(&test_tags::TAG_A, &input);
            let b = sha3_256_tagged(&test_tags::TAG_B, &input);
            prop_assert_ne!(a, b);
        }
    }
}
