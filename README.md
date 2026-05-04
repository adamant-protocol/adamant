# Adamant Protocol Whitepaper

**Version:** 0.1 (draft)
**Status:** In active development
**Last updated:** May 2026

## Reading order

This whitepaper is structured to be read sequentially. Each section assumes the previous ones. Skim sections 0–2 for the vision; sections 3–11 are the technical specification; section 12 is the constitutional commitment.

| # | Section | Status |
|---|---------|--------|
| 0 | [Abstract](./00-abstract.md) | Draft |
| 1 | [Introduction & Motivation](./01-introduction.md) | Draft |
| 2 | [Design Principles](./02-design-principles.md) | Draft |
| 3 | [Cryptographic Foundation](./03-cryptographic-foundation.md) | Draft |
| 4 | [Identity & Accounts](./04-identity-accounts.md) | Draft |
| 5 | [Object Model & State](./05-object-model-state.md) | Draft |
| 6 | Execution & Virtual Machine | Pending |
| 7 | Privacy Layer | Pending |
| 8 | Consensus | Pending |
| 9 | Networking & Mempool | Pending |
| 10 | Economics & Incentives | Pending |
| 11 | Genesis & Constitution | Pending |
| 12 | Conclusion & Open Problems | Pending |

## Notation

Throughout this document:

- `MUST`, `SHOULD`, `MAY` follow [RFC 2119](https://datatracker.ietf.org/doc/html/rfc2119) conventions for normative requirements
- Code blocks in `rust` denote actual or anticipated reference implementation syntax
- Mathematical notation follows standard cryptographic literature; primitives are introduced when first used
- "The chain", "the protocol", and "Adamant" are used interchangeably
- "ADM" refers to the native token; the formal name is reserved until economics are finalised in section 10

## Versioning

This whitepaper uses semantic versioning. Major version increments (1.0, 2.0) require justification in section 12 and have implications for implementation roadmaps. Minor versions (0.x) are draft revisions during specification development.

A v1.0 release indicates the specification is considered complete and frozen for the genesis implementation.
