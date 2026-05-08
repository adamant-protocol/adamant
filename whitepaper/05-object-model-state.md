# 5. Object Model & State

This section specifies how Adamant represents data on the chain. It is the longest technical section in the whitepaper because the object model touches every other component: it determines what transactions can do, what the virtual machine operates on, what the consensus mechanism orders, what the privacy layer shields, and what the recursive verification proves.

The protocol's data model is **object-based**. The chain's state is a collection of independent objects, each owned by an account or shared between accounts according to declared rules, each carrying its own validation logic and mutability declaration. This is the model used by Sui (Move objects), with significant divergences specific to Adamant's privacy and credible-neutrality requirements.

The object model deliberately rejects three alternatives:

1. **The account-balance model** (Ethereum, Solana, Cosmos). State is a flat key-value mapping from account addresses to balances and contract storage. Every transaction touches global mutable state. This model is the easiest to reason about but the hardest to parallelise, and it requires every validator to process every transaction to know any state.

2. **The pure UTXO model** (Bitcoin, Cardano). State is a set of unspent transaction outputs; transactions consume some and produce others. Highly parallelisable but limited in expressiveness; smart-contract programmability requires substantial workarounds.

3. **The actor model** (TON, Internet Computer). State is partitioned into independent actors that communicate by asynchronous message-passing. Highly parallelisable but introduces a difficult programming model and requires reasoning about message ordering across actors.

The object model preserves the parallelism of UTXOs, the expressiveness of accounts, and the modularity of actors. It is the modern consensus among new Layer 1 designs (Sui, Aptos with Move, the various Move-derivative chains) for good reason: it is what works.

## 5.1 What an object is

An Adamant object is a typed, addressed, ownership-tracked piece of state. Every object has the following fields:

```
Object {
    id:            ObjectId,        // 32-byte unique identifier
    type_id:       TypeId,          // identifier of the object's type definition
    owner:         Ownership,       // who can mutate this object
    mutability:    Mutability,      // how the object's code/rules can change
    contents:      Bytes,           // type-specific serialized data
    version:       u64,             // monotonic version counter
    metadata:      ObjectMetadata,  // protocol-managed bookkeeping
}
```

Each field is specified below.

### 5.1.1 ObjectId

The object's unique identifier on the chain. 32 bytes, computed as `SHA3-256(domain_tag || creation_tx_hash || creator_address || creation_index)`. Once assigned, an `ObjectId` never changes. Object identifiers are stable across the object's lifetime: an object that exists at version 1 has the same `ObjectId` at version 1,000,000.

The `creation_tx_hash` is the `TxHash` of the transaction that created this object, computed per section 6.0.4. The `creator_address` and `creation_index` are declared in the transaction's `created_objects` list per section 6.0.2.

This is in contrast to UTXO models, where each "version" of a piece of state has a distinct identifier. Stable identifiers make programs easier to write (a contract holds a reference to a specific object across many transactions) and make the privacy model simpler (one anonymity set per long-lived object, rather than a fresh anonymity set per output).

### 5.1.2 TypeId

The identifier of the object's type. Object types are themselves on-chain objects (specifically, instances of the `Type` meta-type, registered through the type-registration mechanism in section 6). The `TypeId` references the type definition that specifies:

- The schema of the object's `contents` field (what fields it has, what their layouts are)
- The set of operations valid on objects of this type (the object's "methods" in object-oriented terminology)
- Invariants the protocol enforces on every state transition involving objects of this type
- Default mutability rules for objects of this type at creation (which the creator may override per-object)

A `TypeId` is itself a 32-byte hash of the type's canonical definition. Two distinct type definitions with identical canonical encodings produce the same `TypeId`; this is intentional and supports content-addressed type registration.

### 5.1.3 Ownership

The protocol supports four ownership modes:

- **`Address(addr)`**: the object is owned by a single account. Only transactions authorised under that account's validation logic may mutate the object. This is the default for user-held assets such as token balances, NFT-like unique items, and personal data.

- **`Shared`**: the object has no single owner; any transaction may mutate it, subject to the object's own validation rules. Shared objects are the basis for all multi-party applications: decentralised exchanges, lending pools, governance contracts, registries. Mutations of shared objects require consensus (section 8) because two transactions touching the same shared object may conflict.

- **`Immutable`**: the object can never be mutated after creation. Useful for published documents, code modules, type definitions, and other objects intended to be permanent reference material. Immutable ownership is distinct from `IMMUTABLE` mutability declarations (section 5.3): an immutable-owned object cannot be mutated by anyone, while an `IMMUTABLE`-mutability object cannot have its *rules* changed but can still have its `contents` mutated according to those rules.

- **`Group(g)`**: the object is owned by a *group object*, which is itself an object on the chain. The group's validation logic determines whether a given transaction is authorised to mutate the group-owned object. This is the mechanism for multi-signature ownership, organisational ownership, and complex shared-control patterns. The group is itself owned by some entity (an address, another group, or `Shared`), giving rise to nested ownership trees.

Ownership is a property of the object, not of the account. An account holds a set of objects; transferring an object to another account is a state transition that updates the object's `owner` field, leaving the object's identity and contents otherwise unchanged.

**Ownership transitions.** An object's ownership may be transferred subject to the rules of its current ownership mode and the object's mutability declaration. Specifically: an `Address`-owned object may be transferred by the owning account; a `Shared` object may not be made `Address`-owned without explicit consent in the protocol's transition logic; an `Immutable` object's ownership cannot change (it remains permanently un-owned); a `Group`-owned object's ownership transitions follow the group's rules.

### 5.1.4 Mutability

This is the field that operationalises Principle V (mutability as a property of objects, not the chain). Every object declares its mutability at creation, and the declaration is itself immutable: an object created `IMMUTABLE` cannot become `OWNER_UPGRADEABLE`; an object created `OWNER_UPGRADEABLE` cannot become `IMMUTABLE` except via the `UPGRADEABLE_UNTIL_FROZEN` mechanism, which itself was declared at creation.

The protocol defines six mutability variants:

```
enum Mutability {
    Immutable,
    OwnerUpgradeable {
        owner: AccountId,
    },
    VoteUpgradeable {
        token_type: TypeId,
        approval_threshold: u32,    // basis points: 10000 = 100%
        quorum_threshold: u32,      // basis points
        voting_period_secs: u64,
        execution_delay_secs: u64,
    },
    UpgradeableUntilFrozen {
        owner: AccountId,
        // The Mutability field itself does not change after `freeze`;
        // the object's Lifecycle field transitions to Frozen, and the
        // (UpgradeableUntilFrozen, Frozen) combination is what blocks
        // upgrades at the consensus layer. See section 5.4.1.
    },
    Custom {
        upgrade_validator: TypeId,  // type of validator object that authorises upgrades
        validator_id: ObjectId,
    },
    Forked {
        // for objects created by forking another object;
        // inherits original's mutability with restrictions, see section 5.5
        original: ObjectId,
        fork_height: u64,
    },
}
```

Each variant is detailed below.

#### `Immutable`

The object's code, rules, and validation logic are permanently fixed at creation. The object's `contents` field may still change according to the rules of the object's type, but the rules themselves never change.

This is the strongest mutability declaration. A user interacting with an `Immutable` object knows, with cryptographic certainty, that the rules of engagement cannot be altered after the fact.

Use cases: financial primitives (token contracts, escrow contracts, lending markets) where users commit substantial value and require certainty that the rules cannot be retroactively changed; digital monuments (commemorative records, public-record archives); standard libraries and well-known reference implementations.

#### `OwnerUpgradeable { owner }`

The object's code and rules may be changed by transactions authorised under the specified owner account. This is the most permissive standard mutability mode.

Use cases: rapidly-iterating early-stage applications; contracts whose authors retain full operational control; private internal tools; applications where the user is also the owner.

**Trust model.** Users interacting with `OwnerUpgradeable` objects must trust the owner not to make changes that disadvantage them. The protocol does not constrain the owner; it only ensures that the user is *aware* of the owner's authority. Wallets `MUST` display the owner's account when surfacing an `OwnerUpgradeable` object's mutability, so users can make informed decisions about whether to interact.

#### `VoteUpgradeable { token_type, approval_threshold, quorum_threshold, voting_period_secs, execution_delay_secs }`

The object's code and rules may be changed by a vote of token holders, where:

- `token_type`: the `TypeId` of the token whose holders are eligible to vote
- `approval_threshold`: minimum percentage of cast votes that `MUST` approve the change (in basis points; 5000 = 50.00%, 6700 = 67.00%)
- `quorum_threshold`: minimum percentage of total token supply that `MUST` participate for the vote to be valid
- `voting_period_secs`: duration of the voting window
- `execution_delay_secs`: delay between vote success and upgrade application, allowing token holders who object to exit before the change takes effect

This mode supports decentralised governance of contracts. A typical configuration for a community-governed application: 67% approval threshold, 30% quorum, 7-day voting period, 7-day execution delay.

**Important note on credible neutrality.** This mutability mode applies to *individual objects*, not to the protocol itself. The protocol's own consensus rules, virtual machine, and validity logic are `Immutable` by construction (Principle I, section 11). `VoteUpgradeable` is a tool that *applications* can use, not a backdoor through which the protocol itself can be governed.

#### `UpgradeableUntilFrozen { owner }`

A common pattern: the object is `OwnerUpgradeable` for a period (during which the owner iterates on the implementation), and at some later point, the owner calls a `freeze` operation that converts the object's mutability permanently to `Immutable`. After freeze, the object behaves identically to one declared `Immutable` at creation.

This mode is the recommended pattern for many production applications. The owner can fix bugs and deploy improvements during the early operational period; once the application has matured, the owner relinquishes that power and commits to the current implementation forever. Users who interact with the object before freeze trust the owner; users who interact after freeze trust no one.

**Cannot un-freeze.** The freeze operation is one-way. Once frozen, an object cannot be unfrozen, even by the original owner, even by a future fork, even by the protocol itself. This is enforced at the protocol layer, not by convention.

**Wallet display.** Wallets `MUST` distinguish between "frozen" and "still upgradeable" states for `UpgradeableUntilFrozen` objects, so users can see clearly which trust model they are operating under at the time of interaction.

#### `Custom { upgrade_validator, validator_id }`

The object's upgrade rules are specified by a separate validator object (itself a regular Adamant object, with its own type and rules). When an upgrade is proposed, the protocol invokes the validator's `validate_upgrade` method with the proposed change as input; the validator returns *valid* or *invalid*.

This is the protocol's escape hatch for upgrade logic that doesn't fit the standard patterns. Examples:

- **Multi-stage approval.** An upgrade requires approval from a board of trustees AND a community vote AND a 30-day waiting period.
- **Time-restricted upgradeability.** The object is upgradeable only during specified maintenance windows.
- **Conditional upgrades.** Upgrades are permitted only if the object's current state meets specified preconditions.
- **Cross-object dependencies.** Upgrades require the simultaneous upgrade of related objects.

The cost of `Custom` is complexity: users wishing to understand the trust model must inspect the validator object. Wallets `SHOULD` provide tooling that surfaces well-known validator patterns by name (e.g. "this object uses the standard 3-stage governance validator") rather than presenting raw validator code.

#### `Forked { original, fork_height }`

Reserved for objects produced by the chain-fork mechanism specified in section 11. A `Forked` object inherits its predecessor's rules but with restrictions designed to ensure that forks do not produce ambiguous claims of authority. End users do not encounter `Forked` mutability in normal operation.

### 5.1.5 Contents

A type-specific serialized payload. The schema is specified by the object's type (section 5.1.2). The protocol does not interpret `contents` directly; it is the virtual machine's responsibility (section 6) to deserialize, manipulate, and re-serialize this field according to the type definition.

`contents` size is bounded per object. The current bound is 1 MiB; objects requiring more state are expected to split themselves into multiple linked objects. This bound exists to ensure that any single object can be loaded into memory by a validator with reasonable hardware.

### 5.1.6 Version

A monotonically-increasing 64-bit counter, incremented on every state transition that mutates the object. The version field is essential to the consensus mechanism (section 8): two transactions both attempting to mutate the same object at the same version conflict, and only one can be ordered first; the second fails with a version conflict.

The version field is also the basis of the protocol's *causal ordering* property (anticipated in section 1, fully specified in section 8). Two transactions touching disjoint sets of object versions are causally independent and can be processed in any order, in parallel. Two transactions touching the same object version are causally dependent and require consensus to determine which executes first.

### 5.1.7 Metadata

Protocol-managed bookkeeping fields, not under the user's control:

- `created_at_height`: the consensus height (section 8) at which the object was created
- `last_modified_height`: the consensus height of the most recent state transition
- `creator`: the account that created the object
- `storage_rent_paid_through`: the consensus height through which storage rent has been paid (section 5.6)
- `proof_commitment`: cryptographic commitment to the object's history, used by the privacy layer (section 7) and recursive verification (section 8). The commitment is a KZG commitment on BLS12-381 (section 3.9.2), serialised as a compressed G₁ element (48 bytes).

Users do not write to metadata fields directly; they are updated by the protocol as a side-effect of valid state transitions.

### 5.1.8 Canonical serialisation

Every object, every component of an object, and every value that flows through consensus has a single canonical byte representation. Canonical serialisation is consensus-critical: every conforming Adamant implementation must produce byte-identical encodings of the same logical value, or hashes diverge and consensus breaks.

The protocol uses **BCS (Binary Canonical Serialization)** as its canonical encoding, the same format deployed by Sui, Aptos, and the broader Move ecosystem. BCS was designed specifically for blockchain consensus contexts: it produces a unique encoding for each value (no ambiguity in field ordering, no optional padding, no variable-length integer encodings without canonical resolution), it is compact, and it has a stable specification with mature implementations.

BCS encoding rules used by the protocol:

- Integers: little-endian fixed-width for `u8` through `u128`; ULEB128 for collection lengths.
- Booleans: single byte, `0x00` for false, `0x01` for true.
- Sequences (`Vec<T>`): ULEB128 length prefix followed by elements in order.
- Structs: fields serialised in source-declaration order with no separators.
- Enums: ULEB128 variant tag followed by the variant's payload.
- Fixed-size arrays: elements in order with no length prefix.

This is the standard BCS specification; the protocol does not deviate from it. Any value that hashes into consensus — `ObjectId` derivation (section 5.1.1), `TypeId` derivation (section 5.1.2), `Address` derivation (section 4.2), state commitments, transaction hashes — first canonically serialises to BCS bytes, then hashes those bytes with SHA3-256 under an appropriate domain tag (section 3.3.1).

Implementations `MUST` use a BCS-conformant encoder and `MUST NOT` introduce protocol-level fields that BCS cannot represent canonically (for instance: `HashMap` with non-deterministic iteration order, floating-point values, or self-referential structures).

## 5.2 State as a graph of objects

The chain's global state at any moment is the set of all live objects. State transitions are caused by transactions, which take a set of input objects, perform computation, and produce a set of output objects. An object's "history" is the sequence of versions it has passed through, each version produced by a specific transaction.

This is fundamentally different from the global-mutable-state model of account-based chains. Adamant has no global state vector that all validators must agree on at every instant; it has a graph of object histories that validators agree on independently per-object.

### 5.2.1 Causal ordering

Two transactions are *causally dependent* if and only if they read or write at least one common object version. Two transactions that touch disjoint object versions are *causally independent*.

The consensus mechanism (section 8) imposes total ordering only on causally dependent transactions. Causally independent transactions are not ordered relative to each other at the protocol layer; they can be processed in parallel by any validator, in any order, with deterministic results.

This is the core property that makes Adamant's throughput target (200,000+ TPS) achievable. In real-world workloads, the vast majority of transactions are causally independent: Alice paying Bob does not depend on Carol paying Dan. Consensus needs to order them only when they collide, which for typical workloads is a small fraction of total transactions.

The chain's history can therefore be visualised as a directed acyclic graph: nodes are object versions, edges are transactions that read or write objects, and the graph's "shape" reflects the actual causal structure of the chain's activity. Validators agree on the shape of this graph; they do not agree on a single sequential history because no such history exists for causally independent activities.

### 5.2.2 No global state root, but per-object commitments

Account-based chains compute a single global state root after every block — a Merkle (or Verkle) hash of the entire state. This is convenient for light-client verification but expensive to maintain at high throughput, because every transaction touches the global root.

Adamant takes a different approach. Each object maintains its own commitment in its `metadata.proof_commitment` field. The chain's "state root" at any point is the aggregated commitment over all live objects, computable from the per-object commitments without re-hashing the entire state.

This change has two consequences:

- **State updates are local.** A transaction touching N objects updates N commitments, not the entire global state. Throughput scales with object-level parallelism.
- **Recursive proofs are compositional.** Section 8's recursive verification works by aggregating per-object validity proofs, rather than proving validity of monolithic state transitions. This is what enables phone-verifiable verification.

The per-object commitment is computed using KZG vector commitments over BLS12-381 (specified in section 3.9.2). The aggregation across objects uses Halo 2 recursive proofs (section 3.9.1).

## 5.3 The mutability declaration is enforced by consensus

This subsection makes explicit a property that has been implied throughout: **mutability declarations are not enforced by convention or by smart-contract code; they are enforced by the protocol's consensus rules.**

Concretely, when a validator processes a transaction that proposes to upgrade an object's code or rules, the validator checks the target object's `mutability` field directly. If the field is `Immutable`, the upgrade transaction is invalid and rejected at the consensus layer, regardless of what the rest of the transaction says. The validator does not invoke any smart contract to determine whether the upgrade is permitted; the permission is a structural property of the object.

This is in deliberate contrast to Ethereum's proxy patterns, where upgradeability is implemented in user-level smart-contract code and where bugs or unexpected interactions in that code can produce upgradeability behaviours the user did not anticipate. Adamant's mutability is a first-class protocol concept, with the same status as ownership, with no possibility of user-level code violating its constraints.

**This is the property that makes mutability-as-declaration trustworthy.** A user inspecting an `Immutable` object knows that no path in any contract can render it mutable. A user inspecting an `UpgradeableUntilFrozen` object knows that the freeze operation will, in fact, transition the object to permanent immutability at the protocol layer. The mutability declaration is a constitutional fact, not a programming convention.

## 5.4 Object lifecycle

An object passes through a defined lifecycle:

1. **Creation.** A transaction explicitly creates the object, specifying its type, owner, mutability, initial contents, and any other type-specific parameters. The object is assigned an `ObjectId`, set to version 1, and added to the chain state.

2. **Active.** The object exists and is subject to mutation per its rules. State transitions produced by valid transactions update its `contents`, `owner`, or other fields, increment its version, and update its commitments and metadata.

3. **Frozen** (only for `UpgradeableUntilFrozen`). The owner has called the `freeze` operation. The object's `Mutability` field remains `UpgradeableUntilFrozen`; the object's `Lifecycle` field changes to `Frozen`. The combination — `UpgradeableUntilFrozen` + `Frozen` — is what blocks further upgrades at the consensus layer; the `Mutability` field itself is never mutated post-creation. State transitions per the existing rules continue to be valid: contents may be updated through the type's existing logic, the object may be archived if rent is not maintained (lifecycle step 4), and the object may be destroyed through the type's existing destroy-logic (lifecycle step 5). What freeze prohibits is rule upgrades, not contents-evolution or termination through pre-existing rules.

4. **Archived.** If the object's storage rent (section 5.6) is not maintained, the object enters an archived state. Archival applies regardless of the object's `Mutability` field and regardless of whether the object is `Active` or `Frozen` at the time of rent depletion: rent is mutability-independent and freeze-independent. Archived objects' contents are pruned from validator working storage; only their commitment hash is retained. Archived objects cannot be referenced by new transactions until restored. Restoration requires paying the accumulated rent and submitting a proof (provided by archival nodes) of the object's most recent active contents.

5. **Destroyed.** Some objects are explicitly destroyed by their type's logic — for example, a redeemed coupon, a fulfilled escrow, a settled bet. Destruction is a state transition that removes the object from the active state set. Destroyed objects are pruned from working storage but their existence is permanently recorded in the chain's history; their `ObjectId` cannot be reused. Destroyed is terminal: no further lifecycle transitions occur from this state, and any subsequent reference to the `ObjectId` is invalid at the consensus layer.

The lifecycle is enforced by the protocol; type-specific logic determines which transitions occur, but cannot violate the lifecycle's structural properties.

### 5.4.1 The transition graph

The legal transitions between non-`Creation` lifecycle states are:

| From → To       | Active                           | Frozen                          | Archived                         | Destroyed                        |
|-----------------|----------------------------------|---------------------------------|----------------------------------|----------------------------------|
| **Active**      | Self (in-rules contents update)  | `freeze` op; only `UpgradeableUntilFrozen` | Rent depletion        | Type-logic destruction           |
| **Frozen**      | **Forbidden** (freeze is one-way per §5.1.4) | Self (in-rules contents update; freeze is one-way) | Rent depletion        | Type-logic destruction           |
| **Archived**    | Restoration (preserves pre-archival lifecycle — see below) | n/a (cannot be referenced while archived) | Self                  | **Forbidden** (must restore first) |
| **Destroyed**   | n/a (terminal)                   | n/a (terminal)                  | n/a (terminal)                   | Self                             |

Several properties of this graph deserve explicit statement:

- **`Active → Frozen` occurs exclusively through the freeze operation.** No other path produces lifecycle-`Frozen` state. The freeze operation is invoked only on objects with `Mutability::UpgradeableUntilFrozen`; objects with any other mutability cannot reach `Lifecycle::Frozen` through valid protocol operations.

- **`Frozen → Active` is forbidden.** Per section 5.1.4, freeze is one-way "even by a future fork, even by the protocol itself." No protocol operation un-freezes an object.

- **`Frozen → Destroyed` is permitted via the type's pre-existing destroy-logic.** The freeze operation locks rule changes, not the object's existence. A frozen escrow that becomes ready to settle, for example, is destroyed through the same logic that would destroy an active escrow; freeze does not strand the object.

- **Restoration preserves the pre-archival lifecycle.** When an object is archived from `Active`, restoration returns it to `Active`. When an object is archived from `Frozen`, restoration returns it to `Frozen`. This is required by section 5.1.4's freeze-is-one-way invariant: any restoration semantics that landed Frozen objects in `Active` would constitute a backdoor un-freeze through the archival round-trip, contradicting the freeze guarantee.

- **`Archived → Destroyed` is forbidden.** Type-logic operates on an object's contents; archived objects have no contents in working storage; therefore type-logic-driven destruction cannot execute on an archived object. To destroy an archived object, an actor must first restore it (paying accumulated rent and providing the contents proof per section 5.6.2), at which point the object becomes destructible through normal type-logic. This preserves the property that destruction is always an explicit, content-driven decision rather than a side effect of rent depletion.

- **Restoration is not a version-incrementing transition.** A restored object resumes at the version it held at archival time. Causal ordering (section 5.2.1) requires version continuity across the archival round-trip; treating restoration as a version increment would invalidate every reference held by other objects to the pre-archival object.

- **Destroyed is terminal.** No transition out of `Destroyed` exists. Any transaction referencing a destroyed `ObjectId` is invalid at the consensus layer.

## 5.5 Object derivation: forks, copies, and references

Object identity is unique. Two objects with the same `ObjectId` are the same object. The protocol does not support arbitrary cloning of objects; what it supports are several specific derivation operations:

- **Reference.** Many objects can hold references to a single shared object. A reference is a 32-byte `ObjectId` field that the holding object's logic can use to dispatch operations to the referenced object. References are cheap and create no new state.

- **Copy of contents.** A new object is created whose `contents` are derived from another object's `contents` (typically by transforming or summarising it). The new object has a fresh `ObjectId` and an independent existence; modifications to either object do not affect the other. Copying is a normal `create` operation; the protocol does not distinguish copies from any other newly-created object.

- **Fork.** A reserved operation specified in section 11. Forking applies in the context of a chain fork — a divergence where part of the validator set has migrated to a new client implementation with different consensus rules. Forked objects inherit their predecessor's content and rules but carry the `Forked` mutability variant, signalling that they exist on a forked timeline. End users do not encounter forked objects in normal operation.

- **Snapshot.** A reserved operation that creates a content-addressed read-only handle to an object's state at a specific version. Snapshots support certain advanced patterns (proof-of-historical-state, audit trails) without violating the unique-identity property, because snapshots are themselves identified by `(ObjectId, version)` pairs rather than fresh `ObjectId`s.

## 5.6 Storage and rent

The chain's state grows monotonically as objects are created. Without a counterbalance, validators would eventually be unable to store the full state on commodity hardware, centralising the network. The protocol prevents this through a state-rent mechanism.

### 5.6.1 The rent model

Every object is associated with a *storage rent rate*: a per-byte-per-second cost charged to the object's "rent account." The rent account is funded by the object's owner (or by anyone, for shared objects) through normal token transfers. When the rent account is depleted, the object enters the *archived* lifecycle state.

**Rent rates.** The rent rate is a chain-wide parameter set at genesis and not modifiable post-genesis. The exact value is specified in section 10 (Economics & Incentives); for context, the design target is that one year's storage of one kilobyte of object content costs approximately the same as one normal transaction's fee.

**Pre-payment.** Object creation includes pre-payment of rent for some initial period (default: one year). Owners may top up the rent account at any time.

### 5.6.2 Archival is not deletion

When an object is archived, its `contents` are pruned from validator working storage, but its `ObjectId` and commitment remain in chain state. The object is *unreferenceable* in new transactions but not *forgotten*. Specifically:

- The object's `proof_commitment` remains in the chain's recursive proof.
- The object's `ObjectId` cannot be reassigned to a new object.
- The object's contents are retained by *archival nodes* — voluntary participants who store full historical state for cryptographic or social reasons. Archival nodes are not part of consensus and are not required by the protocol; they are a community resource.
- The object can be *restored* by paying accumulated rent plus a restoration fee, and submitting a proof (provided by an archival node) that the object's pre-archival contents are unchanged. Restoration returns the object to its pre-archival lifecycle state — `Active` if it was `Active` at archival time, `Frozen` if it was `Frozen` at archival time. The restored object resumes at its pre-archival `version`; restoration is not a version-incrementing transition. (See section 5.4.1 for the lifecycle-transition graph these properties are part of.)

This model ensures that state size is bounded by *active* state, not total state ever created. Inactive state is preserved for historical and forensic purposes but does not impose ongoing cost on consensus participants.

### 5.6.3 Rent-exempt objects

Some objects, by their nature, cannot be archived without violating the chain's invariants. Examples:

- **Type definitions.** If a type definition were archived, every object of that type would become uninterpretable. Type definitions pay one-time rent at creation that grants permanent active status.
- **Active validator records.** A validator's record is essential to consensus; it cannot be archived while the validator is participating.
- **Recently-created objects.** Objects in their first 30 days are rent-exempt to prevent denial-of-service attacks where an adversary creates objects faster than rent payments can be collected.

The exempt categories are specified in section 11 (Genesis & Constitution) and cannot be expanded after genesis.

## 5.7 Privacy and the object model

This section has described objects as if they were universally visible. They are not. Section 7 (Privacy Layer) specifies how the object model interacts with the protocol's privacy properties, but the high-level relationship is:

- **Object existence is public.** The set of `ObjectId`s in active state is observable by all participants. The total state size is observable. The number of objects created and destroyed per consensus epoch is observable.

- **Object contents may be shielded.** An object's `contents` may be encrypted such that only specified parties (the owner, holders of view keys, parties to a multi-party object) can decrypt them. Shielded `contents` are accompanied by zero-knowledge proofs that state transitions involving the object are valid, computable without decrypting the contents.

- **Ownership may be hidden.** An object's `owner` field may itself be shielded, such that the chain records only that the object is owned by *some* account, without recording which account. Stealth-address mechanisms (section 7) support this.

- **Mutability declarations are public.** The `mutability` field is always in clear text. This is required by Principle V's user-visibility requirement: users `MUST` be able to query an object's mutability before interacting, even if they cannot read its contents.

The privacy model is therefore selective: structural properties of objects (existence, type, mutability, version-counter advancement) are public; semantic properties (contents, ownership in detail, the meaning of state transitions) may be shielded. Section 7 specifies the cryptographic constructions in detail.

## 5.8 Worked example: a token

To make the foregoing concrete, here is the structure of a typical fungible-token object on Adamant:

**Type definition** (a `Type` object, registered once):

- `name`: "ExampleToken"
- `symbol`: "EXM"
- `decimals`: 6
- `total_supply_logic`: defines how supply changes (mint/burn rules)
- `transfer_logic`: defines how token balances move between accounts
- `default_mutability`: `Immutable` (recommended for production tokens)

**Token-supply object** (a single `Shared` object representing the global token supply):

- `id`: derived from creation
- `type_id`: the ExampleToken type
- `owner`: `Shared`
- `mutability`: `Immutable`
- `contents`: encodes total supply, supply schedule, mint/burn authority
- `version`: increments on every supply change

**User-balance objects** (one per holder, `Address`-owned):

- `id`: derived per-balance
- `type_id`: the ExampleToken-balance type
- `owner`: `Address(holder_account)`
- `mutability`: `Immutable`
- `contents`: encrypted; encodes the holder's balance
- `version`: increments on every transfer

A transfer transaction reads the sender's balance object, the recipient's balance object, and (potentially) the supply object; produces updated versions of the sender's and recipient's balance objects; and emits a zero-knowledge proof that the transfer is valid (sender's balance decreases by amount X, recipient's balance increases by amount X, no funds created or destroyed). The supply object is not modified, only read.

This pattern — global supply object plus per-holder balance objects — is the canonical fungible-token implementation on Adamant. It supports parallel processing (transfers between disjoint pairs of accounts do not conflict), it supports privacy (balances are shielded; transfers use stealth addresses; observers see only that *some* account transferred to *some other* account), and it is verifiable by recursive proofs (the chain's recursive proof attests that all balance changes are well-formed across all token types).

Section 6 (the virtual machine) specifies how this pattern is expressed in the protocol's smart-contract language. Section 7 specifies the privacy mechanisms that shield the contents.