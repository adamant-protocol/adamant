# BLS12-381 test vectors — coverage notes

This directory is intentionally light: it contains no checked-in
external KAT files. The reasoning is recorded here so a future
contributor or auditor doesn't have to re-derive it.

## Why no checked-in external KATs

BLS12-381 has two well-known signature variants, parameterised by
which group hosts the public key and which hosts the signature:

- **min_pk** (small public keys): pk in G1 (48 bytes), sig in G2
  (96 bytes). Used by Ethereum consensus, Filecoin, Chia, and most
  major BLS deployments.
- **min_sig** (small signatures): pk in G2 (96 bytes), sig in G1
  (48 bytes). Used by Adamant per whitepaper section 3.4.3,
  because signatures are exchanged every consensus vote whereas
  public keys are registered once per validator — small
  signatures matter more at consensus throughput.

The widely-circulated KAT suites — Ethereum's
[`bls12-381-tests`](https://github.com/ethereum/bls12-381-tests),
the IRTF [`draft-irtf-cfrg-bls-signature`] examples, the IETF
hash-to-curve [`draft-irtf-cfrg-hash-to-curve`] BLS12-381 G2
ciphersuite vectors — all target **min_pk**. Their byte encodings
are not transferable: a 48-byte "pubkey" hex from an Eth2 vector
encodes a G1 point, which for us is a Signature, not a PublicKey;
a 96-byte "signature" encodes a G2 point, which for us is a
PublicKey, not a Signature. Cross-applying them would require
relabelling and would not exercise our wrapper's actual sign/verify
codepaths because the DST and message layouts differ.

The min_sig variant is in IRTF-spec scope but is not the path most
test-vector publishers cover. We searched the IRTF draft, Filecoin,
Chia, Ethereum, and Algorand BLS test repositories; none ship
min_sig sign/verify KATs directly usable by this wrapper.

## What we rely on instead

Three layers, in order of independence:

1. **Upstream `blst` is itself tested against IRTF and Ethereum
   vectors** at the algorithm level. blst implements both variants
   via the same C primitives; passing min_pk vectors validates the
   underlying group, pairing, and hash-to-curve operations. The
   variant-specific layer is a thin wrapper around the same maths.
   blst's audit history is recorded in `SECURITY.md`.
2. **Inline self-consistency tests** in
   `crates/adamant-crypto/src/bls.rs::tests`: 22 tests covering
   roundtrip correctness, tampering rejection, determinism, byte
   round-trips, constant-time equality, zeroize discipline, and
   the four aggregation cases the whitepaper calls out
   (same-message aggregate, multi-message aggregate verify,
   tampering of one signature in an aggregate, tampering of the
   aggregate signature bytes after the fact).
3. **DST sourcing** is asserted at compile-time (the DST is taken
   from the centralised `domain.rs` registry, not an inline literal)
   and verified at test-time
   (`tests::dst_is_sourced_from_domain_registry` checks the byte
   string against the whitepaper §3.4.3 specification verbatim).

## Re-evaluate when

- A min_sig BLS KAT suite appears upstream. Filecoin and Chia
  occasionally ship variant-specific tests; check their repos
  before mainnet.
- The protocol's BLS variant is reconsidered. Whitepaper revision
  would be required to change from min_sig.
- We move to a different BLS implementation. A wrapper change of
  this magnitude would be a deliberate decision with its own audit
  posture; KATs would be revisited then.
