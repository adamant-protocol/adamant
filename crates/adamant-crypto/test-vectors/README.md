# Adamant cryptographic test vectors

Canonical test vectors for every primitive wrapped by `adamant-crypto`.
A wrapper passing its vector suite is a necessary (not sufficient) condition
for that wrapper to ship.

## Layout

One subdirectory per primitive, created when the primitive's wrapper lands.
Each subdirectory contains:

- `README.md` — vector source (RFC, FIPS document, IRTF draft, or named
  reference implementation), file format, and the wrapper test that
  consumes the vectors.
- One or more `*.json` / `*.txt` / `*.kat` files — the vectors themselves,
  in the format used by the upstream source where possible.

## Planned subdirectories

Created on demand as each primitive's wrapper is implemented.

| Subdirectory | Source |
|--------------|--------|
| `sha3/` | FIPS 202 known-answer tests; NIST CAVP byte-oriented vectors |
| `shake256/` | FIPS 202 KATs |
| `blake3/` | BLAKE3 reference test vectors (`reference_impl/test_vectors`) |
| `poseidon/` | Generated against `halo2_gadgets` reference values; generation source documented in subdirectory README |
| `ed25519/` | RFC 8032 test vectors |
| `ml-dsa/` | NIST FIPS 204 KATs |
| `bls/` | IRTF `draft-irtf-cfrg-bls-signature` vectors; Ethereum consensus-spec vectors |
| `chacha20poly1305/` | RFC 8439 test vectors |
| `kzg/` | Ethereum consensus-spec KZG vectors |

## Policy

- A primitive without published official test vectors **must** document the
  absence in its subdirectory README and use generated vectors from a
  named reference implementation. The generation source (or a hash of the
  reference output) is checked in alongside the vectors.
- Vector tests run in CI as part of `cargo test --workspace`.
- Vector files are committed verbatim; they are **not** generated at test
  time. Generated-once-checked-in is a deliberate choice — it makes the
  vectors part of the audit surface.
- Adding or modifying a vector file is called out in the commit message,
  with a citation to the source document or generation procedure.
