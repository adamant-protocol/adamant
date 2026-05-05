# Threshold encryption test vectors — coverage notes

This directory is intentionally light: it contains no checked-in
external KAT files. The reasoning is recorded here so a future
contributor or auditor doesn't have to re-derive it. The shape
parallels the [BLS coverage notes](../bls/README.md); this is the
second primitive in the workspace where standardised external vectors
do not exist.

## Why no checked-in external KATs

The hashed-ElGamal threshold KEM construction in whitepaper §3.6
(Boneh-Franklin / Baek-Zheng lineage on BLS12-381) is deployed in
production by Shutter Network on Gnosis Chain — the only large-scale
deployment we could find. Shutter's reference implementation
([shutter-network/rolling-shutter](https://github.com/shutter-network/rolling-shutter))
exposes vectors against its own integration: epoch-encoded identities,
specific DSTs, specific KDF tag bytes. None of those match Adamant's
parameter choices verbatim. Cross-applying them would require
re-deriving every value, which defeats the purpose of an external KAT.

Specifically, the parameters that differ between Shutter and Adamant:

- **Hash-to-curve DST.** Shutter uses
  `SHUTTER_V01_BLS12381G1_XMD:SHA-256_SSWU_RO_`. Adamant uses
  `BLS_TE_BLS12381G1_XMD:SHA-256_SSWU_RO_ADAMANT_v1`
  (whitepaper §3.6.1, registered in `domain.rs::BLS_TE_HASH_TO_CURVE`).
  Different DST → different `H_TE(identity)` → different decryption
  shares for the same identity.
- **KDF.** Shutter derives the symmetric key via HKDF-SHA-256 over the
  GT element. Adamant derives it via tagged-SHAKE-256 with the
  `ADAMANT-v1-threshold-kdf` registry tag (whitepaper §3.6.1,
  `domain.rs::THRESHOLD_KDF`). Different KDF → different symmetric key
  for the same `(GT, U, identity)` transcript.
- **Identity encoding.** Shutter uses an integer epoch directly.
  Adamant prescribes `epoch (8 bytes BE) || salt (32 bytes)` per the
  §3.6.1 last paragraph, but the crypto layer in this crate accepts
  arbitrary `&[u8]` and the §9 mempool envelope enforces the format.

The IRTF has no draft for threshold encryption on BLS12-381, and no
academic paper publishes byte-level vectors for the construction at
parameters matching Adamant's. We searched Shutter's repos, the BLS
working group, and the threshold-cryptography literature; none ship a
KAT directly applicable to this wrapper.

## What we rely on instead

Three layers, in order of independence:

1. **Upstream `blst` is itself tested against IRTF and Ethereum
   vectors at the algorithm level.** Every primitive operation the
   threshold module composes — G₁ hash-to-curve, G₂ scalar
   multiplication, pairings, Z_r arithmetic — is exercised by blst's
   own KAT suite, which targets the BLS12-381 maths irrespective of
   how it is composed. blst's audit history is recorded in
   `SECURITY.md`. The threshold module's correctness reduces to
   "Lagrange interpolation in the G₁ exponent and a tagged-SHAKE
   transcript over a `(GT, U, identity)` triple"; the underlying
   primitives are validated upstream.
2. **Inline self-consistency tests** in
   `crates/adamant-crypto/src/threshold.rs::tests` — over 30 tests
   covering:
   - End-to-end encapsulate → distribute → combine → decapsulate
     roundtrip at multiple `(t, n)` parameters (3-of-5, 1-of-1).
   - Subset invariance: different threshold-sized subsets of the same
     validator set reconstruct the same combined share. This is the
     algebraic property of Lagrange interpolation; failure indicates a
     bug in the coefficient computation.
   - Oversample invariance: using more than `t` shares still
     reconstructs the correct combined share.
   - Per-share verification accepts valid shares and rejects
     wrong-identity, wrong-index, and tampered-bytes inputs.
   - Combine internally re-verifies and rejects malformed shares
     before Lagrange interpolation, per the consensus-criticality
     note in whitepaper §3.6.1.
   - **Structural identity:** `decryption_share(s_i, identity)`
     produces the exact same 48-byte encoding as a BLS signature on
     `identity` under `s_i` with the threshold-encryption DST. This
     is the spec's "DecryptionShare" subsection made executable.
   - **Cross-protocol attack rejection:** a BLS signature under the
     `BLS_SIG_HASH_TO_CURVE` DST does NOT validate as a decryption
     share under the `BLS_TE_HASH_TO_CURVE` DST. This is the spec's
     "Domain separation" subsection made executable.
   - Lagrange-coefficient unit tests for the 1-of-1 (λ=1) and 2-of-2
     (λ_1 + λ_2 = 1) base cases, derived directly from the algebra.
3. **DST and KDF tag sourcing** is asserted at compile-time (both
   tags are taken from the centralised `domain.rs` registry, not
   inline literals) and verified at test-time
   (`te_dst_is_sourced_from_domain_registry` and
   `kdf_tag_is_sourced_from_domain_registry` check the byte strings
   against the whitepaper §3.6.1 specification verbatim).

## Re-evaluate when

- An IRTF or academic publication lands a threshold-KEM KAT suite
  for BLS12-381 at parameters compatible with Adamant's. The most
  likely path: an IRTF working-group draft or a new threshold-crypto
  paper that publishes both DST and KDF specifics. Cross-check at
  every Phase 1 dependency review.
- We move to a different threshold-encryption construction. The
  hashed-ElGamal KEM is deliberately conservative; a switch to a
  post-quantum threshold scheme (whitepaper §3.6.4) would warrant
  fresh KATs against that scheme's reference implementation.
- A second large-scale deployment of this construction publishes its
  KATs in a way that lets us cross-check the underlying maths even
  with different DST/KDF parameters. This would be useful as an
  algorithm-level sanity check even at incompatible parameters.

Re-evaluate before mainnet regardless; absence of variant-specific
KATs at mainnet would be a known limitation worth flagging in audit
prep, parallel to the `bls/` coverage note.
