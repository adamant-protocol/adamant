# Adamant Protocol Whitepaper

**Version:** 0.1 (complete draft)
**Status:** Awaiting public review
**Last updated:** May 2026

## Reading order

This whitepaper is structured to be read sequentially. Each section assumes the previous ones. Skim sections 0–2 for the vision; sections 3–11 are the technical specification; section 12 is the conclusion.

| # | Section | Status |
|---|---------|--------|
| 0 | [Abstract](./00-abstract.md) | Draft |
| 1 | [Introduction & Motivation](./01-introduction.md) | Draft |
| 2 | [Design Principles](./02-design-principles.md) | Draft |
| 3 | [Cryptographic Foundation](./03-cryptographic-foundation.md) | Draft |
| 4 | [Identity & Accounts](./04-identity-accounts.md) | Draft |
| 5 | [Object Model & State](./05-object-model-state.md) | Draft |
| 6 | [Execution & Virtual Machine](./06-execution-vm.md) | Draft |
| 7 | [Privacy Layer](./07-privacy-layer.md) | Draft |
| 8 | [Consensus](./08-consensus.md) | Draft |
| 9 | [Networking & Mempool](./09-networking-mempool.md) | Draft |
| 10 | [Economics & Incentives](./10-economics-incentives.md) | Draft |
| 11 | [Genesis & Constitution](./11-genesis-constitution.md) | Draft |
| 12 | [Conclusion & Open Problems](./12-conclusion.md) | Draft |

## Single-file version

A merged single-file version of all sections is available at [`adamant-whitepaper-v0.1-draft.md`](./adamant-whitepaper-v0.1-draft.md) for ease of reading or printing.

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

## Status: complete first draft

This whitepaper now has a complete first draft of all 12 sections (~38,000 words, approximately 130-150 pages typeset). It awaits:

- Public review by the broader cryptographic and blockchain community
- Iteration based on feedback
- Reference implementation experience that may surface issues
- A v1.0 freeze before genesis

Issues, pull requests, and substantive review are welcome at [github.com/adamant-protocol/adamant](https://github.com/adamant-protocol/adamant).
