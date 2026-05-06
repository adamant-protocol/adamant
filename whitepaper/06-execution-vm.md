# 6. Execution & Virtual Machine

This section specifies how transactions are executed on Adamant: the smart-contract language, the virtual machine, the parallel execution model, and the resource accounting (gas) framework. It builds directly on the object model of section 5 and is the layer at which user-defined logic interacts with chain state.

The protocol's execution model is governed by three requirements:

1. **Resource safety.** The language must make value-related bugs (double-spend, accidental destruction, reentrancy) structurally impossible, not merely conventionally avoidable. This is non-negotiable for a chain whose users hold significant value in shielded form, where the auditability of contracts is reduced and the cost of a single class of bugs can be catastrophic.

2. **Parallel execution.** The VM must support deterministic parallel execution at scale, exploiting the causal-independence property of the object model (section 5.2.1). Sequential execution as in Ethereum's EVM is incompatible with the throughput targets in Principle IV.

3. **Privacy compatibility.** The language must integrate cleanly with the privacy layer (section 7). Shielded execution — running a contract while keeping its inputs, intermediate state, and outputs encrypted — must be a first-class concept, not an afterthought.

## 6.0 Transactions: the input to execution

This subsection specifies the canonical `Transaction` data type — the input the rest of section 6 operates on. Every other subsection (the language, the runtime, gas, deployment) consumes Transactions; pinning the type's fields, encoding, and derived `TxHash` here is therefore prerequisite to specifying any of them precisely.

A `Transaction` is the protocol's unit of state-change request. It is created off-chain (typically by a wallet), signed off-chain by the authorising account, submitted to the network, and either executed (advancing chain state) or rejected (with no effect on chain state). Transactions are the only mechanism by which users cause state to change.

### 6.0.1 The body / evidence split

A `Transaction` has two parts:

```
Transaction {
    body: TxBody,
    auth: AuthEvidence,
}
```

The **body** carries the operation payload — what the transaction is asking to do. The **authorisation evidence** carries the signatures, witnesses, and other non-body data that authorise the body's execution. The split exists to solve the signature-signs-itself problem: signatures cover `BCS(body)` and live in `auth`, so the body's canonical encoding does not depend on the signatures it produces.

The `TxHash` (section 6.0.4) is computed over the body alone, not the full Transaction. This means two Transactions with identical bodies but different auth evidence produce the same `TxHash`. That property is intentional: it ensures the `TxHash` identifies the *operation* a user committed to, not the particular signature instance carrying that commitment. Replay protection is the body's responsibility (via nonces or version-pinned read sets), not the hash's.

### 6.0.2 The body

```
TxBody {
    authorising_account: AccountRef,
    fee_payer: Option<AccountRef>,
    read_set: Vec<(ObjectId, Version)>,
    write_set: Vec<ObjectId>,
    created_objects: Vec<CreatedObject>,
    gas_budget: GasBudget,
    call: CallParams,
    nonce: u64,
}
```

**`authorising_account`.** The account whose validation logic (per section 4.3) is invoked at execution-pipeline step 1. For transparent transactions, `AccountRef::Cleartext(Address)` names the account directly. For shielded transactions, `AccountRef::Shielded(StealthCommitment)` names it via a stealth-address commitment (section 4.7), preserving privacy of the authorising account while still enabling validation-logic dispatch.

**`fee_payer`.** Optional. When `None`, the fee payer is the `authorising_account`. When `Some(account)`, the fee payer is a different account whose own authorisation must also appear in `AuthEvidence` (per the sponsored-transaction model in section 6.3.4). The same shielded/cleartext options apply.

**`read_set`.** The objects this transaction reads, declared as `(ObjectId, Version)` pairs. The version pin protects against read-write conflicts: if any read object's version has advanced beyond the declared version at execution time, the transaction is rejected without execution. Wildcards are forbidden — the read set must be a statically declared list, both for the parallel scheduler (section 6.2.3) and for the privacy layer (section 7) which requires the read set to be circuit-encoded for shielded transactions.

**`write_set`.** The pre-existing objects this transaction modifies, declared as `ObjectId`s. Modification requires the object to be in the read set as well (read-then-write); the write set is therefore a subset of the read set's `ObjectId`s. Objects whose contents are read but not modified appear only in the read set.

**`created_objects`.** Objects to be created within this transaction, declared explicitly so their ObjectIds are derivable per section 5.1.1. Each `CreatedObject` carries:

```
CreatedObject {
    creator: Address,
    creation_index: u64,
    type_id: TypeId,
    initial_owner: Ownership,
    initial_mutability: Mutability,
}
```

The `(creator, creation_index)` pair, combined with this transaction's `TxHash` (computed over the body, which contains this declaration), produces the new `ObjectId` per the section 5.1.1 formula. This is well-defined despite the apparent circularity: the `TxHash` is computed over the body bytes, and the body's bytes are fixed before hashing — the body declares its created objects by `(creator, creation_index)` only, and the `ObjectId` is derived from the resulting `TxHash` afterward. No object's `ObjectId` appears in the body's declaration of itself.

**`gas_budget`.** A six-dimension cap matching section 6.3.1's gas dimensions:

```
GasBudget {
    computation: u64,
    storage: u64,
    rent: u64,
    bandwidth: u64,
    proof_verification: u64,
    proof_generation: u64,
}
```

The transaction aborts on the first dimension exhausted; the user cannot trade unused budget in one dimension for additional consumption in another. This preserves section 6.3.1's motivation for multi-dimensional pricing: dimensions correspond to distinct validator resources, and a single combined cap would obscure which resource a transaction actually stresses.

**`call`.** The operation payload — which function to invoke, on which target, with which arguments:

```
CallParams {
    target_module: ModuleRef,
    target_function: FunctionId,
    type_arguments: Vec<TypeId>,
    arguments: Vec<Value>,
}
```

Module deployment is not a special transaction variant. To deploy a new module, a transaction calls the standard-library function `adamant::module::deploy` (section 6.5) with the module's bytecode as an argument. This keeps `TxBody` shape uniform — every transaction is a function call — and matches the standard-library pattern where protocol-level operations are exposed as system-function calls rather than as kernel discriminators.

**`nonce`.** A monotonic counter scoped to the `authorising_account`, ensuring distinct transactions from the same account have distinct bodies (and therefore distinct `TxHash`es) even when their other fields match. The nonce also defends against replay across forks of the chain. The protocol-enforced rule is that a transaction's `nonce` must equal one greater than the highest nonce previously executed for `authorising_account`; gaps are not permitted.

### 6.0.3 The auth evidence

```
AuthEvidence {
    signatures: Vec<Signature>,
    witnesses: Vec<Witness>,
}
```

The evidence is a flat list of signatures and witnesses. The structure is deliberately simple: validation logic in the authorising account interprets them according to the account's declared scheme (single-sig, dual-sig, threshold-sig, etc., per section 4.3). The protocol does not impose a fixed signature scheme on transactions — the account's validation logic does.

For sponsored transactions (section 6.3.4) where `fee_payer` is set, the fee payer's authorisation must also appear in `signatures`. The fee payer's account validation logic runs alongside the authorising account's during the execution pipeline.

For shielded transactions, the authorising account's signature is replaced (or accompanied) by zero-knowledge witnesses proving authority without revealing the account. Section 7 specifies the construction.

The auth evidence is excluded from the `TxHash`. Modifying signatures or witnesses does not change the `TxHash`; only modifying the body does. This property simplifies the signature-signs-itself problem and matches standard practice across the field.

### 6.0.4 TxHash derivation

The transaction hash is computed over the canonical BCS encoding of the body alone:

```
TxHash = sha3_256_tagged(TX_HASH, BCS(body))
```

where `TX_HASH` is the registered domain tag `b"ADAMANT-v1-tx-hash"` per section 3.3.1, and `BCS(body)` is the canonical encoding per section 5.1.8. The `TxHash` is the protocol-level identifier of a transaction's *operation*; two transactions with byte-identical bodies have the same `TxHash` regardless of how they were authorised.

This `TxHash` value is what flows into `ObjectId` derivation per section 5.1.1, into chain-history records, into the read/write conflict detector, and into recursive proof aggregation per section 8.

### 6.0.5 Privacy mode is implicit

A transaction's privacy mode (transparent or shielded) is determined by the annotation on its target function (`#[transparent]` or `#[shielded]` per section 6.1.2), not by an explicit field on the `Transaction` itself. A transaction whose `call.target_function` is a `#[shielded]` function is a shielded transaction; one targeting a `#[transparent]` function is a transparent transaction. The bytecode validator (section 6.2.2 step 3) rejects transactions whose target function's annotation conflicts with the validator's static analysis of read/write set contents — for example, a transparent function attempting to read a shielded object.

A single transaction targets a single function; a transaction cannot mix transparent and shielded annotations within itself. Composite operations that span multiple functions are achieved by decomposition into multiple transactions, not by mixed-annotation calls.

### 6.0.6 Canonical encoding and consensus

Like every consensus-critical type, the `Transaction` and its sub-types are BCS-encoded canonically per section 5.1.8. Field ordering in this subsection's struct definitions is the canonical encoding order; reordering fields is a hard fork. Adding fields is also a hard fork — the transaction format is genesis-fixed in the same sense as the gas table (section 6.3.2) and the bytecode format (section 6.2.1). Validators reject transactions whose BCS encoding contains unknown fields or non-canonical ordering.

### 6.0.7 Inner-type canonical encodings

Several types referenced in sections 6.0.1 / 6.0.2 / 6.0.3 are themselves consensus-critical in their canonical encoding (because they appear inside `BCS(body)` bytes that flow into the `TxHash`) but their *semantic* or *cryptographic* construction is specified elsewhere or in later sections. This subsection pins the canonical encoding of each — what bytes each type produces under BCS — without specifying the construction of the underlying value. The two concerns are separable: the encoding boundary is what consensus validators depend on, while the construction of the underlying value is the concern of the section that defines the cryptographic or semantic role.

**`Version`.** Type alias for `u64`, matching the `version` field on `Object` per section 5.1.6. Encoded as a little-endian 8-byte integer.

**`Signature`.** A discriminated union over the protocol's signature schemes (sections 3.4.1 / 3.4.2):

```
Signature {
    Ed25519([u8; 64]),       // BCS variant tag 0x00
    MlDsa65([u8; 3309]),     // BCS variant tag 0x01
    MlDsa87([u8; 4627]),     // BCS variant tag 0x02
}
```

The variant set is fixed at genesis. Adding a new signature scheme is a hard fork. The fixed sizes match the signature outputs of the schemes specified in section 3.4. Validators decode signatures by reading the variant tag, then the appropriate fixed-size byte array.

**`StealthCommitment`.** A 32-byte fixed-size value used in `AccountRef::Shielded(StealthCommitment)` per section 6.0.2. The cryptographic construction — what the bytes mean as a stealth-address commitment — is specified in section 7 (privacy layer). Section 6.0.7 pins only the encoding: `[u8; 32]`. Validators that hash a `TxBody` containing `AccountRef::Shielded(_)` produce a `TxHash` over those 32 bytes; the interpretation of the bytes (as a curve point, as a Pedersen commitment, etc.) is section 7's concern but does not affect the encoding.

**`Witness`.** A length-prefixed byte vector used in `AuthEvidence.witnesses` per section 6.0.3. Encoded as `Vec<u8>` (ULEB128 length prefix followed by raw bytes). The contents — a zero-knowledge proof, a signature witness, an authentication tag, etc. — are specified in section 7. Section 6.0.7 pins only that the encoding is a BCS-canonical byte vector; the contents are opaque to the encoding layer.

Implementation note: because `Witness` is part of `AuthEvidence` (excluded from the `TxHash` per section 6.0.4), changing the contents-level interpretation of `Witness` bytes in a future revision does not alter `TxHash` values for transactions whose witnesses are byte-identical. This decoupling is a deliberate consequence of the body/evidence split.

**`ModuleRef`.** A newtype wrapping `ObjectId`:

```
ModuleRef(ObjectId)
```

per section 6.4.1's framing of modules as first-class objects. Encoded as the wrapped `ObjectId` (32 bytes, no additional discriminator).

**`FunctionId`.** A UTF-8 string, length-bounded to 255 bytes:

```
FunctionId(String)
```

with the constraint that the byte length of the string's UTF-8 encoding is at most 255. Functions are identified by name within their containing module, not by integer index. This decouples transaction encoding from the module's internal function table layout — a module upgrade that re-orders its functions does not invalidate pending transactions referencing those functions, because the transaction names them. The 255-byte bound is a structural constraint enforced at decode time; transactions exceeding the bound are rejected. Encoded as `Vec<u8>` containing the UTF-8 bytes (ULEB128 length prefix followed by bytes).

**`Value`.** A discriminated union covering Adamant Move's value taxonomy:

```
Value {
    U8(u8),                      // BCS variant tag 0x00
    U16(u16),                    // BCS variant tag 0x01
    U32(u32),                    // BCS variant tag 0x02
    U64(u64),                    // BCS variant tag 0x03
    U128(u128),                  // BCS variant tag 0x04
    U256([u8; 32]),              // BCS variant tag 0x05, big-endian
    Bool(bool),                  // BCS variant tag 0x06
    Address(Address),            // BCS variant tag 0x07
    Vector(Vec<Value>),          // BCS variant tag 0x08
    Struct(StructValue),         // BCS variant tag 0x09
}

StructValue {
    type_id: TypeId,
    fields: Vec<Value>,
}
```

The `Value` enum's variant set covers Adamant Move's primitive types, addresses, the polymorphic `vector<T>` constructor (encoded recursively as `Vector(Vec<Value>)`), and user-defined structs. The variant tags are fixed at genesis. Adding a new primitive type is a hard fork.

For `Struct(StructValue)`, the `type_id` identifies the struct type per section 5.1.2, and `fields` carries the struct's field values in the canonical order specified by the type's definition. The mapping from `fields` ordering to the struct's named fields is a property of the type definition (section 6.2.1), not the `Value` encoding. Two struct values with the same `type_id` and byte-identical `fields` BCS encoding are equal by definition; their semantic interpretation (which field is which) requires the type definition.

**Summary.** This subsection's encodings are genesis-fixed and consensus-critical. The cryptographic construction of `StealthCommitment` (section 7), the contents of `Witness` (section 7), the structural layout of any specific user-defined struct value (section 6.2.1), and the semantic interpretation of any field at the application layer are all out of scope here. The encoding pinned here is what `BCS(body)` and `BCS(witnesses)` produce when validators flow these types through canonical serialisation.

## 6.1 The Adamant Move language

The protocol's smart-contract language is **Adamant Move**, a derivative of the Move language originally developed by Facebook (Diem project, 2018–2022) and now maintained as an open standard by the Move community, with significant production deployment in Sui and Aptos.

### 6.1.1 Why Move

Move was designed from first principles around the problem of representing digital assets safely. Its core innovation is a *linear type system* in which values denoting assets cannot be copied, accidentally discarded, or implicitly destroyed. Operations on assets must explicitly account for their movement: a function that takes a `Coin` as input must explicitly transfer it, store it, or destroy it; the compiler refuses to compile code that does anything else.

This property is enforced at the type level, not by runtime checks. A contract that incorrectly handles assets does not compile; it cannot be deployed; it cannot run. This makes whole classes of bugs that have plagued Solidity contracts (double-spends due to integer underflow, lost funds due to forgotten transfers, reentrancy attacks due to ordering bugs) structurally impossible in Move.

The protocol adopts Move because:

1. **Linear types are the right primitive for value-bearing systems.** Every other language requires programmer discipline; Move enforces correctness at the compiler.

2. **Move's object model aligns with Adamant's object model.** Move's "resources" map cleanly to Adamant's `Address`-owned objects; Move's "shared objects" (in Sui's variant) map cleanly to Adamant's `Shared` objects. The languages are designed for the same world.

3. **Production track record.** Sui mainnet (May 2023) and Aptos mainnet (October 2022) have processed over $30B in cumulative volume across hundreds of millions of transactions on Move. The language is not experimental.

4. **Existing tooling.** Compilers, formal verifiers (the Move Prover), debuggers, and IDE support exist. Adamant inherits this ecosystem rather than rebuilding it.

5. **Active research community.** Mysten Labs, Aptos Labs, and academic researchers continue to publish on Move's foundations. Adamant participates in this community rather than diverging from it.

### 6.1.2 What "Adamant Move" extends

Adamant Move is Move with three protocol-specific extensions. Where standard Move and Adamant Move agree, programs written in standard Move work without modification on Adamant; where they differ, the differences are documented here.

**Extension 1: Mutability declarations as first-class syntax.**

Standard Move does not have native syntax for object mutability declarations as defined in section 5.3. Adamant Move adds the following construct to module declarations:

```move
module 0xCOFFEE::example_token {
    use adamant::object;
    use adamant::mutability;

    // The mutability declaration is part of the type definition,
    // visible to readers, enforced by the protocol.
    #[mutability(immutable)]
    public struct ExampleToken has key {
        id: object::ObjectId,
        balance: u64,
    }

    // ...
}
```

Available declarations: `#[mutability(immutable)]`, `#[mutability(owner_upgradeable(addr))]`, `#[mutability(vote_upgradeable(token_type, thresholds))]`, `#[mutability(upgradeable_until_frozen(addr))]`, `#[mutability(custom(validator_id))]`. The compiler refuses to compile a module that lacks an explicit mutability annotation; defaults are not provided, because defaulting to anything other than the strictest option silently weakens the user's expectations.

**Extension 2: Shielded and transparent execution annotations.**

Functions in Adamant Move are annotated with their privacy requirement:

```move
// Operates entirely on shielded inputs and shielded state.
// Produces a zk-SNARK proof of correct execution without
// revealing inputs or state to validators.
#[shielded]
public fun private_transfer(
    sender: &mut Coin,
    recipient: address,
    amount: u64,
) { /* ... */ }

// Operates on transparent (cleartext) inputs and state.
// Validators see all inputs and outputs.
#[transparent]
public fun public_donation(
    coin: Coin,
    pool: &mut DonationPool,
) { /* ... */ }

// Default: contract author has not specified.
// Compiler error - explicit choice required.
public fun unspecified() { /* ... */ }
```

The compiler refuses to compile functions without an explicit privacy annotation. This forces contract authors to make a deliberate choice about each function's privacy properties, rather than producing transparent contracts by default.

The protocol enforces these annotations at execution time. A `#[shielded]` function invoked in a transparent transaction is an error; a `#[transparent]` function invoked under a shielded execution context is an error. Section 7 specifies the cryptographic mechanisms by which shielded execution operates.

**Extension 3: Privacy primitives.**

Adamant Move provides built-in primitives for the privacy operations specified in section 7. Contract authors do not implement these from scratch; they call protocol-provided functions:

- `adamant::privacy::shielded_balance` — type representing an encrypted balance
- `adamant::privacy::stealth_address` — derive a one-time recipient address
- `adamant::privacy::view_key_release` — produce a sub-view-key for selective disclosure
- `adamant::privacy::range_proof` — prove a value lies in a range without revealing it
- `adamant::privacy::membership_proof` — prove an element belongs to a set without revealing which

These primitives compile to circuit operations in the protocol's Halo 2 circuit library (section 7), invisibly to the contract author. The contract author thinks of them as ordinary function calls; the compiler emits the corresponding circuit witnesses.

### 6.1.3 What Adamant Move does not change

Adamant Move preserves Move's core semantics unchanged. Specifically:

- The linear type system, including the `key` and `store` ability constraints
- Module structure, function visibility, and abilities
- Generic types and phantom type parameters
- Bytecode format. Adamant Move bytecode is a strict superset of Sui-Move bytecode, with the additional protocol-specific instructions and metadata documented in subsection 6.2.1. The Sui-Move dialect is the substrate; the protocol-specific extensions are additive.
- The Move Prover specification language for formal verification
- Standard library types (vectors, options, strings, etc.)

A developer fluent in Move learns Adamant Move in days. The differences are additive, not breaking.

### 6.1.4 What Adamant Move excludes

Adamant Move excludes the following constructs that exist in some Move dialects:

- **Dynamic dispatch via runtime type discovery.** Move's type system is statically resolved; dynamic dispatch in some dialects is implemented through trait-like patterns. Adamant Move declines these patterns to preserve verifiability properties.

- **Native functions (NFTs in the language sense, not in the asset sense).** Standard Move permits "native functions" implemented by the runtime in C++ for performance. Adamant Move does not: every function is implemented in Move bytecode and verifiable. Performance-critical primitives are provided through the Halo 2 circuit interface (section 7) rather than through bytecode-bypass mechanisms.

- **Direct global storage access.** Some Move dialects permit modules to read and write global storage by address. Adamant Move requires all storage access to be mediated through object references, consistent with section 5's object model.

These exclusions tighten the language's verifiability and parallelism properties at modest cost to expressiveness.

## 6.2 The Adamant Virtual Machine (AVM)

The Adamant Virtual Machine (AVM) is the runtime that executes Adamant Move bytecode. It is implemented in Rust (Principle VI: standard tooling) and operates as one component of the validator node.

### 6.2.1 Bytecode format

The AVM executes **Adamant Move bytecode**, a strict superset of Sui-Move bytecode with protocol-specific extensions for privacy operations, recursive proof primitives, and Adamant's gas-accounting model. This subsection specifies the bytecode at the level of detail required for an independent implementation: the dialect choice and its rationale, the module file format, the privacy and mutability annotations at bytecode level, the instruction set, operand encoding, the validation rules, and the per-instruction gas costs.

#### 6.2.1.1 Dialect choice: Sui-Move

Three Move dialects exist in production with meaningful differences:

- **Diem-Move** (the original, maintained at github.com/move-language/move). Has no native object model; objects are represented through global storage primitives (`move_to`, `move_from`, `borrow_global`).
- **Sui-Move** (Mysten Labs' fork, maintained at github.com/MystenLabs/sui). Replaces Diem's global storage with a first-class object model where objects have unique IDs, ownership types (`Address`-owned, `Shared`, `Immutable`), and are passed by reference between transactions.
- **Aptos-Move** (Aptos Labs' fork, maintained at github.com/aptos-labs/aptos-core). Retains Diem's global storage model and adds resource accounts and table abstractions.

The protocol selects **Sui-Move as the bytecode substrate**. The reasoning is structural: section 5's object model is itself Sui-derived, and Sui-Move bytecode integrates with that object model at the bytecode level — instructions for object packing, transfer, and freezing operate directly on object references rather than through global storage. Building Adamant on Diem-Move would require us to extend Diem-Move with object-model integration that already exists in Sui-Move; building on Aptos-Move would inherit Aptos's global storage model that conflicts with section 5's "all state is an object" position.

The dialect choice is genesis-fixed. Migrating to a different Move dialect post-genesis would be a hard fork affecting every deployed module.

**What "strict superset" means.** Every valid Sui-Move module that respects Adamant's tightened verifier rules (section 6.2.1.6) is a valid Adamant Move module: same instruction set, same module file format, same type system, same verifier rules. Adamant adds:

- New instruction opcodes for privacy operations, recursive proof primitives, and protocol-specific cryptographic operations (specified in section 6.2.1.4).
- Module-level metadata fields encoding mutability declarations per section 5.1.4 and section 6.1.2 (specified in section 6.2.1.3).
- Function-level metadata fields encoding privacy annotations per section 6.1.2 (specified in section 6.2.1.3).
- Tightened verifier rules excluding the constructs listed in section 6.1.4 (specified in section 6.2.1.6).

A program that uses none of Adamant's extensions, carries the required metadata, and respects Adamant's tighter verifier rules is bytecode-identical to its Sui-Move equivalent.

**Implementation note.** This subsection treats Sui-Move's `move-binary-format` and `move-bytecode-verifier` crates as a test-time cross-validation reference for the inherited substrate's semantics. A conforming Adamant implementation may vendor those crates and exercise them at test time to confirm that Adamant's own deserializer and verifier reach the same accept/reject decision as Sui's on pure-Sui modules. The protocol's behaviour on the inherited subset is defined by sections 6.2.1.1 through 6.2.1.8 of this specification; Sui's reference implementation is consulted at test time to confirm semantic parity, not as the binding source of truth. The vendored crates do not appear in the production binary's dependency graph — section 6.2.1.8 specifies the Adamant-native deserializer and verifier that own the deploy-time pipeline and runtime, with the vendored Sui crates serving as test-only cross-validation reference.

The strict-superset property is at the *language* level: every valid Sui-Move module that respects Adamant's tightened verifier rules is a valid Adamant Move module, and an Adamant module that uses no extensions is bytecode-identical to its Sui-Move equivalent. The vendored Sui crates, by contrast, recognise only the Sui-base subset — Sui's `move-binary-format` deserializer rejects any opcode byte outside Sui's instruction set with `UNKNOWN_OPCODE`, and Sui's `move-bytecode-verifier` operates on Sui's `Bytecode` enum which has no representation for Adamant extensions. The Adamant-native deserializer and verifier specified in section 6.2.1.8 handle the full Adamant superset directly; cross-validation against the vendored Sui crates on pure-Sui modules confirms semantic parity for the inherited subset.

#### 6.2.1.2 Module file format

A deployed module is stored in `Object.contents` (per section 5.1.5 and section 6.4.1) as a byte string whose interior structure is the **CompiledModule** format defined by Sui-Move (`move-binary-format` crate). The format is itself a stable subset of the Move bytecode binary format originally specified by Diem.

The module structure consists of a four-byte magic number `0xA1, 0x1C, 0xEB, 0x0B` (the Move file format magic, inherited unchanged across Diem, Sui, and Aptos), a `u32` version number, and pools of definitions and references. The pools are, in canonical order: `module_handles` (modules this module imports), `struct_handles` and `field_handles` (struct types and their fields), `function_handles` (function signatures), `friend_decls` (friend module declarations), generic instantiation tables (`struct_def_instantiations`, `function_instantiations`, `field_instantiations`), `signatures` (parameter and return type lists; this is Move's bytecode-format-internal type-list type, distinct from the cryptographic `Signature` of section 6.0.7), `identifiers` (string pool for names), `address_identifiers` (address pool), `constant_pool` (typed constants), `metadata` (Sui-Move metadata entries plus Adamant extensions per section 6.2.1.3), `struct_defs` (struct definitions), and `function_defs` (function definitions, including bytecode bodies).

The structure inside each entry follows Sui-Move's binary format exactly. Genesis modules use the Sui-Move binary format version current at the time of Adamant genesis; future format revisions are hard forks.

**What's stored per function.** Each `FunctionDefinition` carries: a reference to the function's signature in the module's signature pool, the function's bytecode body as a list of instructions (the `Bytecode` enum specified in section 6.2.1.4), local-variable type information, an acquires-list for global resources (always empty in Adamant, since global storage is excluded per section 6.2.1.6), and visibility (`public`, `private`, or `friend`). Adamant-specific privacy annotations are not stored in `FunctionDefinition` itself — they live in a module-level metadata entry (per section 6.2.1.3) so that `FunctionDefinition` remains byte-identical to Sui-Move's layout. The validator (section 6.2.1.6) consults the metadata entry to resolve privacy annotations during verification.

**Encoding boundary.** The CompiledModule bytes themselves are opaque to BCS — they are stored inside the `contents` field of a Module object, and the `contents` field's BCS encoding is a length-prefixed byte vector per section 5.1.5. The bytecode's internal structure is not BCS; it is Sui-Move's binary format extended with Adamant's instruction-set additions per section 6.2.1.4. This is consistent with the encoding/construction split established in section 6.0.7: the protocol's BCS-canonical envelope carries the module bytes, and the bytes' internal interpretation is the bytecode format's concern. Parsing those bytes into an in-memory module representation is specified in section 6.2.1.8.

#### 6.2.1.3 Annotations at bytecode level

Adamant Move's source-level annotations (per section 6.1.2) round-trip into bytecode through metadata entries.

**Mutability declarations** are module-level metadata. The compiler emits a `Metadata` entry on each module with the key `b"adamant.mutability"` and value being the BCS encoding of the `Mutability` enum (per section 5.1.4). The validator (section 6.2.1.6) requires every Adamant module to carry exactly one such metadata entry; modules without it are rejected at deployment.

**Privacy annotations** are module-level metadata. The compiler emits a `Metadata` entry on each module with the key `b"adamant.privacy"` and value being the BCS encoding of `Vec<(FunctionDefinitionIndex, u8)>` — a list of (function index, privacy byte) pairs. The privacy byte values are:

```
PrivacyAnnotation: u8
    0x00 = #[transparent]
    0x01 = #[shielded]
```

The metadata-entry storage location (rather than appending the byte to `FunctionDefinition` directly) preserves byte-faithfulness with Sui-Move's bytecode format per section 6.2.1.1's strict-superset commitment. `FunctionDefinition` is inherited unchanged from Sui-Move; Adamant-specific function metadata lives in module-level metadata entries that the validator (section 6.2.1.6) consults.

Public functions without an entry in this metadata table are rejected by the verifier (matching the source-level requirement in section 6.1.2 that compilers reject unannotated public functions). Private (internal) functions may omit the entry; they inherit the privacy mode of the calling context, and the AVM rejects mixed-mode call chains per section 6.0.5 and the verifier rule in section 6.2.1.6.

**Backward compatibility with Sui-Move.** A standard Sui-Move module without these annotations cannot be deployed on Adamant — the validator rejects it for missing the mutability metadata. This is intentional: Adamant requires explicit mutability and privacy choices on every module, and a Sui module that hasn't made those choices is not yet an Adamant module. Porting a Sui module to Adamant is a one-line change at the module level (adding the mutability declaration) plus per-public-function privacy annotations.

#### 6.2.1.4 Instruction set

The AVM's instruction set is **Sui-Move's bytecode instruction set** (the `Bytecode` enum defined in `move-binary-format::file_format`) plus Adamant-specific extensions. The architecture is **stack-based** — operands are pushed onto an operand stack, instructions consume and produce stack values, and the abstract machine state per function frame is `(stack, locals, pc)`. (Pre-revision drafts of this section described the AVM as register-based; that was a drafting error inconsistent with section 6.1.3's "strict superset of Sui-Move bytecode" claim. Move's bytecode has been stack-based across all three lineages — Diem, Sui, Aptos — and Adamant inherits this architecture.)

**Inherited instruction set.** The protocol inherits the full Sui-Move instruction set as of the binary-format version specified in section 6.2.1.2. The categories below are illustrative for orientation; the authoritative enumeration with opcodes, operand formats, and stack effects is the `Bytecode` enum in Sui's `move-binary-format` crate.

- *Stack and locals:* `Pop`, `Ret`, `BrTrue`, `BrFalse`, `Branch`, `LdU8` through `LdU256`, `CastU8` through `CastU256`, `LdConst`, `LdTrue`, `LdFalse`, `CopyLoc`, `MoveLoc`, `StLoc`.
- *References:* `MutBorrowLoc`, `ImmBorrowLoc`, `MutBorrowField`, `ImmBorrowField`, `ReadRef`, `WriteRef`, `FreezeRef`.
- *Function calls:* `Call`, `CallGeneric`.
- *Struct operations:* `Pack`, `Unpack`, `PackGeneric`, `UnpackGeneric`.
- *Arithmetic and logic:* `Add`, `Sub`, `Mul`, `Mod`, `Div`, `BitOr`, `BitAnd`, `Xor`, `Or`, `And`, `Not`, `Eq`, `Neq`, `Lt`, `Gt`, `Le`, `Ge`, `Shl`, `Shr`.
- *Vector operations:* `VecPack`, `VecLen`, `VecImmBorrow`, `VecMutBorrow`, `VecPushBack`, `VecPopBack`, `VecUnpack`, `VecSwap`.
- *Object operations (Sui-derived):* packing and unpacking of types with the `key` ability, transfer through Sui's object-transfer instructions.
- *Abort:* `Abort`.

**Adamant-specific extensions.** Adamant adds the following instructions in a reserved opcode range above Sui-Move's last opcode, allowing future Sui-Move additions without collision:

- `InvokeShielded(FunctionHandleIndex)` — invoke a `#[shielded]` function. The runtime asserts the caller's privacy context is shielded; if not, the transaction aborts. Stack effect matches `Call`: the operand stack pops one value per function parameter (in declaration order, top-of-stack last) and pushes one value per return value. When the target function's signature contains reference parameters or returns, the borrow-graph effect is identical to Sui-Move's `Call` for the same signature shape — the verifier (section 6.2.1.6) and AVM runtime treat reference inputs and outputs of `InvokeShielded` exactly as they would for an inherited `Call`.
- `InvokeTransparent(FunctionHandleIndex)` — invoke a `#[transparent]` function. The runtime asserts the caller's privacy context is transparent; if not, aborts. Stack effect and reference-safety semantics match `InvokeShielded` (and `Call`) above; the only difference is the runtime privacy-mode assertion.
- `GenerateProof(CircuitId)` — emit a Halo 2 proof witness for the current shielded execution context. Operand is an index into the module's circuit-reference pool. Pops the circuit's input arity (one stack value per declared circuit input, in declaration order) from the stack; pushes a single `Witness` value (per section 6.0.7). The circuit's input arity and per-input types are determined by the circuit signature resolved through the operand's `CircuitId`; the resolution and the input-type list are specified by section 7. At the bytecode layer, the stack effect is parametric in the circuit's signature, similar to how `Call`'s stack effect is parametric in its `FunctionHandle`'s signature.
- `VerifyProof(CircuitId)` — verify a Halo 2 proof. Pops a `Witness` value followed by the circuit's public-input arity (one stack value per declared public input, in declaration order, top-of-stack last); pushes a `bool`. As with `GenerateProof`, the public-input arity and types are determined by the circuit signature resolved through the operand's `CircuitId` per section 7.
- `ReleaseSubViewKey` — produce a sub-view-key per section 4.4 and section 7. Pops the parent view key; pushes the derived sub-key.
- `KzgCommit` — produce a KZG commitment over a vector of field elements per section 3.7.2. Pops the vector; pushes a 48-byte commitment.
- `KzgVerify` — verify a KZG opening proof. Pops the commitment, the opening, and the claimed value; pushes a `bool`.
- `RecursiveVerify` — verify a recursive Halo 2 proof per section 8's recursive verification. Pops the proof value followed by the recursive circuit's public-input arity (one stack value per declared public input, in declaration order, top-of-stack last); pushes a `bool`. The recursive circuit's public-input arity is determined by the circuit signature specified in section 8.5; the stack effect is parametric in that signature in the same shape as `VerifyProof`.
- `Sha3_256` — SHA3-256 hash of a byte vector (per section 3.3.1). Pops a `vector<u8>`; pushes `[u8; 32]`.
- `Blake3` — BLAKE3 hash of a byte vector (per section 3.3.2). Pops a `vector<u8>`; pushes `[u8; 32]`.
- `Ed25519Verify` — verify an Ed25519 signature (per section 3.4.1). Pops public key, message, signature; pushes `bool`.
- `MlDsaVerify65` and `MlDsaVerify87` — verify ML-DSA signatures (per section 3.4.2).
- `BlsVerify` — verify a BLS12-381 signature (per section 3.4.3).
- `ChargeGas(GasDimension)` — charge a specified amount across one of the six gas dimensions (per section 6.0.7's `GasBudget` and section 6.3.1). Pops the amount as `u64`.
- `RemainingGas(GasDimension)` — push the remaining budget for a specified dimension as `u64`. Used by stdlib functions that adapt behaviour based on remaining budget.
- `OutOfGas` — abort the transaction with the out-of-gas error. Used by stdlib functions that detect dimension exhaustion.

The Adamant-specific extensions are documented as a separate enum (`AdamantBytecode`) that the bytecode format includes alongside the Sui-Move base set; the bytecode body of a function is a sequence of instructions where each instruction is either an inherited Sui-Move opcode or an Adamant extension, distinguished by opcode value.

The complete instruction set — inherited and extension — is genesis-fixed. Adding new instructions (whether by Sui-Move upstream additions we choose to incorporate or by Adamant-specific additions) is a hard fork.

**CircuitId resolution.** Section 6.2.1.4 references "an index into the module's circuit-reference pool" as the operand of `GenerateProof` and `VerifyProof`. The pool is not part of section 6.2.1.2's `CompiledModule` layout (which inherits Sui-Move's pool list unchanged). The pool's location and structure — chain-wide circuit registry, per-module pool extending Sui's `metadata`, or a separate per-module pool field — is deferred to section 7 (the privacy layer), where the cryptographic role of Halo 2 circuits is specified. At the bytecode layer, `CircuitId` is an opaque `u16` index; the resolution from index to circuit definition is the privacy layer's concern, applied at runtime when shielded execution invokes `GenerateProof` or `VerifyProof`. This is the encoding/construction split established in section 6.0.7 (canonical encoding pinned now; semantic construction deferred to the section that defines the role) applied to bytecode operands.

#### 6.2.1.5 Operand encoding

Sui-Move's bytecode uses variable-length operand encoding: the opcode byte is followed by zero or more operand bytes whose layout depends on the opcode. Most operands are indices (into the local-variable table, function-handle table, struct-handle table, signature pool, constant pool, etc.) encoded as ULEB128; immediate values are encoded as little-endian fixed-width integers (`LdU64` is followed by 8 little-endian bytes; `LdU128` is followed by 16 little-endian bytes; `LdU256` is followed by 32 little-endian bytes, matching Sui-Move's inherited `write_u256` encoding).

The bytecode-operand encoding for `U256` differs from section 6.0.7's `Value::U256` BCS encoding, where the 32-byte array is interpreted big-endian as a 256-bit integer. The two paths are independent: bytecode operand encoding inherits from Sui-Move per section 6.2.1.1, while transaction-argument encoding follows BCS canonicality per section 5.1.8. The endianness divergence has no observable consequence at the byte level because the two encoding paths never share bytes — bytecode operands appear inside Move binary modules, while BCS-encoded values appear in transaction arguments and on-chain typed values. Auditors verifying `U256` encoding must check the encoding path against the byte's location in the protocol's data flow.

Adamant inherits this encoding unchanged for the Sui-Move base set. Adamant-specific instructions follow the same encoding rules: opcode byte followed by ULEB128 indices or fixed-width immediates as appropriate.

The bytecode stream itself is not BCS-encoded — it is Move's native binary format, opaque to BCS at the protocol layer. BCS canonicality (section 5.1.8) applies to the protocol's consensus types (Transaction, Object, etc.); the bytecode stored inside a Module object is consensus-critical only insofar as the *bytes* are stored and hashed faithfully, not insofar as those bytes follow BCS rules.

**Per-extension operand encodings.** The 17 Adamant-specific extensions per section 6.2.1.4 use the following operand layouts within the framing above:

- `InvokeShielded(FunctionHandleIndex)` and `InvokeTransparent(FunctionHandleIndex)` — operand encoded as ULEB128, matching Sui-Move's `FunctionHandleIndex` encoding for inherited `Call` and `CallGeneric`.
- `GenerateProof(CircuitId)` and `VerifyProof(CircuitId)` — operand encoded as ULEB128. `CircuitId` is treated as an index per section 6.2.1.4's "an index into the module's circuit-reference pool" framing, matching Sui-Move's encoding pattern for other indices (function-handle, constant-pool, struct-handle, etc.).
- `ChargeGas(GasDimension)` and `RemainingGas(GasDimension)` — operand encoded as a single byte variant tag in declaration order: `Computation = 0x00`, `Storage = 0x01`, `Rent = 0x02`, `Bandwidth = 0x03`, `ProofVerification = 0x04`, `ProofGeneration = 0x05`. This matches the variant-tag pattern established in section 6.0.7's `Value` enum encoding.
- The 11 zero-operand extensions (`ReleaseSubViewKey`, `KzgCommit`, `KzgVerify`, `RecursiveVerify`, `Sha3_256`, `Blake3`, `Ed25519Verify`, `MlDsaVerify65`, `MlDsaVerify87`, `BlsVerify`, `OutOfGas`) carry no operand bytes after the opcode byte.

These encodings are genesis-fixed; changing any of them is a hard fork.

#### 6.2.1.6 Validator (bytecode verification)

Before a module is deployed, its bytecode must pass validation. The validator is a static analyser that runs over the module and rejects modules that violate any required property. Deployment is denied for invalid modules; a module that is accepted is guaranteed by the consensus layer to have the validated properties.

The validator runs the **inherited Sui-Move bytecode verifier** (the `move-bytecode-verifier` crate) plus **Adamant-specific additional checks**.

**Inherited checks (from Sui-Move's verifier).** These pass through unchanged:

- *Type safety:* every operand on the stack matches the type expected by the consuming instruction.
- *Reference safety:* borrowed references do not outlive the values they reference; mutable references are not aliased.
- *Linearity:* values without the `copy` ability are never duplicated; values without the `drop` ability are never implicitly discarded.
- *Stack discipline:* stack depth is statically bounded; no stack underflow or runaway growth.
- *Control-flow integrity:* every `Branch` target is a valid instruction within the function; no jumps into the middle of multi-byte instructions.
- *Function-call ABI:* arguments and return values match the function's declared signature.
- *Generic instantiation:* type arguments satisfy the abilities required by the generic parameters (`copy`, `drop`, `key`, `store`).
- *Friend visibility:* friend calls only reach declared friends.

**Adamant-specific additional checks.**

1. **Mutability metadata required.** Every module must carry exactly one `b"adamant.mutability"` metadata entry per section 6.2.1.3. Modules without it are rejected.

2. **Privacy annotation required on public functions.** Every public function must carry a `PrivacyAnnotation` byte (`0x00` for transparent, `0x01` for shielded). Public functions without it are rejected. Private functions may omit the annotation.

3. **Privacy consistency.** A `#[shielded]` function may not contain any `InvokeTransparent` instruction; a `#[transparent]` function may not contain any `InvokeShielded` instruction. The verifier statically checks the entire call graph reachable from each public function and rejects modules where the privacy mode would be violated.

   Privacy consistency is enforced through **defense in depth**: the AVM enforces privacy at runtime as the consensus-binding mechanism (a `#[shielded]` function structurally requires shielded execution context — proof generation infrastructure, encrypted operand stack — and the AVM aborts privacy-mismatched calls at the call boundary regardless of whether deploy-time verification caught the mismatch). The deploy-time static check is the deployer-feedback and gas-trap-prevention layer: it rejects modules whose call graph contains known privacy violations within the limits of what static analysis can prove given the dependencies visible at deploy time. Cross-module call graphs are statically checked at deploy time against the annotations of dependency modules visible on chain at that moment; combined with the upgrade-immutability constraint on privacy annotations (section 6.4.3), this deploy-time guarantee is durable across the lifetime of the deployed module. The runtime check carries the residual binding for any case the static analysis cannot fully verify.

4. **No native functions.** The native-function flag on a function definition (Sui-Move marks runtime-implemented natives this way) must not be set on any function. Per section 6.1.4, every function in Adamant Move is implemented in bytecode. Performance-critical primitives are exposed through Adamant-specific instructions (section 6.2.1.4), not through bytecode-bypass natives.

5. **No global storage instructions.** The Diem-Move global storage instructions (`MoveTo`, `MoveFrom`, `BorrowGlobal`, `Exists`, etc.) must not appear in the bytecode. Per section 6.1.4, all storage access goes through object references. Sui-Move itself phases out these instructions in favour of objects; this rule formalises that policy and rejects any module attempting the legacy patterns.

6. **No dynamic dispatch.** Sui-Move's dynamic-field operations are restricted: a function may use them only if its module carries a metadata entry `b"adamant.allows_dynamic"` whose value is `true`. The default is to disallow them per section 6.1.4. Most Sui-Move modules don't use dynamic fields; those that do typically rely on them for collection types that have first-class object equivalents in Adamant.

   "Dynamic-field operations" are specifically calls to functions whose target module is at address `0x2` and whose module name is either `dynamic_field` or `dynamic_object_field`. This pins the rule's scope at the module level (rather than enumerating individual function names) so that future additions to those Sui standard library modules are automatically captured by the rule without spec amendment. The verifier identifies these calls by inspecting `Call` and `CallGeneric` instructions and resolving their `FunctionHandle` to the target module's `(address, name)` pair via the module's handle tables.

7. **Privacy-circuit instructions in shielded context only.** `GenerateProof`, `VerifyProof`, `RecursiveVerify`, and `ReleaseSubViewKey` may appear only in the body of `#[shielded]` functions or their internal callees. Calling these from a transparent context is rejected at verification time.

8. **Bounded loops.** Loops in the bytecode are bounded at runtime by the gas mechanism per section 6.2.4 ("All loops must have statically-bounded iteration counts or run within a gas budget that bounds them dynamically"). Static loop-bound verification is not required at deployment time; the gas-budget bound at runtime carries the determinism guarantee.

   (Pre-revision drafts of this rule referenced "Sui-Move's existing loop-bound analysis as a starting point." That was a drafting error: Sui-Move's `move-bytecode-verifier::loop_summary` module performs CFG structural analysis — back-edge identification via Tarjan's loop reducibility — rather than iteration-bound analysis. There is no upstream loop-bound analysis to extend. Determinism is established at runtime via section 6.2.4's gas-budget bound; the verifier-level check is a no-op.)

A module that passes all inherited and Adamant-specific checks is **valid** and may be deployed. A module that fails any check is rejected with an error indicating which check failed; the deployment transaction aborts and no rent is consumed for the module that would not have been accepted.

#### 6.2.1.7 Per-instruction gas costs

Per section 6.3.2, gas costs are fixed at genesis and not modifiable post-genesis. Every bytecode instruction has a fixed cost across the six dimensions of the `GasBudget` (per section 6.0.7 and section 6.3.1). Most instructions consume only the `computation` dimension and zero in the others; cryptographic and proof-related instructions consume `computation` plus one or more other dimensions reflecting their resource profile.

The complete cost table is large (≥ 200 instructions × 6 dimensions, mostly zero in five of six dimensions for any given instruction); the table is published as a separate normative appendix to this whitepaper. Reference values across cost categories, illustrative only:

- *Pure stack operations* (`Pop`, `CopyLoc`, `MoveLoc`, `StLoc`): 1–10 computation units; zero in all other dimensions.
- *Arithmetic and logic* (`Add`, `Mul`, `Lt`, `Eq`): width-proportional in computation (u8 cheaper than u256); zero elsewhere.
- *References and field access* (`MutBorrowField`, `ReadRef`, `WriteRef`): computation plus `bandwidth` for references that cross object boundaries.
- *Function calls* (`Call`, `CallGeneric`): computation plus a per-call frame-setup overhead.
- *Object operations* (`Pack` of `key`-bearing types, transfer instructions): computation plus `storage` for any new object created and `rent` for the object's rent prepayment.
- *Cryptographic primitives* (`Sha3_256`, `Ed25519Verify`, `BlsVerify`): computation, proportional to input size and primitive cost. SHA3-256 over n bytes is roughly `100 + 0.5 · n` computation units; Ed25519 verification is roughly 50,000 units; BLS verification is roughly 100,000 units.
- *Privacy operations* (`GenerateProof`, `VerifyProof`, `RecursiveVerify`): consume `proof_generation` and `proof_verification` heavily. A single Halo 2 proof generation is on the order of 10⁹ proof_generation units; verification is on the order of 10⁵ proof_verification units, reflecting the asymmetric cost profile of zero-knowledge proofs.
- *Resource operations* (`ChargeGas`, `RemainingGas`, `OutOfGas`): a flat 1 computation unit; their purpose is to manipulate the gas budget rather than to perform work.

The reference values above are illustrative; the genesis-fixed table in the appendix supplies the exact values. Implementations must match those values exactly. Deviation produces consensus disagreement: validators on different cost tables would diverge on which transactions exhaust their budgets.

The total instruction set is finite and frozen at genesis. New instructions cannot be added without a hard fork (section 11).

#### 6.2.1.8 Module deserializer and verifier architecture

Sections 6.2.1.1 through 6.2.1.7 describe the bytecode language. This subsection describes how a conforming Adamant implementation parses bytecode bytes into an in-memory module representation and runs verification over that representation. The architecture is **fully Adamant-native at deploy-time and runtime**: a conforming Adamant implementation runs entirely independently of Sui-Move's codebase in production builds, with the vendored Sui-Move crates serving as test-only cross-validation reference. A conforming implementation provides its own deserializer, serializer, type definitions, constants, helper utilities, and verifier passes covering both the inherited Sui-Move subset and the Adamant extensions; the vendored Sui-Move crates do not appear in the production binary's dependency graph. This posture makes Adamant **resistant-proof** against upstream Sui changes, shutdowns, vulnerabilities, or governance shifts: once a vendored snapshot is exercised at test time, no future Sui-Move change can affect Adamant's deploy-time accept/reject decisions or runtime behaviour. Two implementations that disagree on whether a given module-bytes input is valid for deployment are not both conforming, regardless of whether either consults Sui-Move. No implementation that depends on Sui-Move's logic at deploy-time or runtime is conforming; test-only, build-tooling-only, and CI-only dependencies on vendored Sui-Move are explicitly permitted, but Sui-Move logic must not execute during deploy-time module verification or runtime VM execution.

(Pre-revision drafts of this subsection described a "Sui-projection" mechanism that fed Adamant modules through Sui-Move's vendored verifier with extension instructions substituted by Sui's `Nop` instruction. Empirical investigation surfaced that 3 of Sui-Move's 4 per-instruction verifier passes — `StackUsageVerifier`, `type_safety`, and `reference_safety` — reject the `Nop` projection for any Adamant extension with nonzero stack, type, or reference effect, which is 16 of 17 extensions. The projection mechanism is therefore not viable: Sui's passes would reject perfectly valid Adamant modules at deployment. The Adamant-native verifier architecture below replaces it. The drafting error is acknowledged here rather than silently revised, in keeping with the audit-trail-honesty pattern established at section 6.2.1.4.)

**The Adamant-native deserializer.** A conforming Adamant implementation provides a deserializer that parses module bytes into an Adamant module representation containing the full Adamant instruction set. The representation extends Sui-Move's `CompiledModule` shape — same module-level pools, same handle tables, same per-function metadata — with one structural change: function bodies are sequences over the Adamant instruction set (Sui-base instructions plus Adamant extensions per section 6.2.1.4) rather than over Sui-Move's `Bytecode` enum alone. The wire encoding for function bodies is specified in section 6.2.1.5; the deserializer parses module-level structure (handle tables, signature pool, identifiers, addresses, constants, metadata, struct definitions, function definition headers) using the binary format defined in section 6.2.1.2, and parses function bodies via the wire-encoding layer.

The deserializer enforces canonical encoding: the deserialized module representation must re-serialize byte-identically to the input. Non-canonical inputs (trailing junk bytes, redundant encodings, or any divergence between input and re-serialization) are rejected. This recovers the canonical-encoding posture that section 6.0.6 establishes for transactions and applies it to module bytecode at the deployment boundary.

**The Adamant-native verifier.** A conforming implementation provides a verifier that operates directly on the Adamant module representation, with full coverage of both the Sui-base subset and the Adamant extensions. The verifier comprises module-level passes (validating structure that does not iterate function bodies) and per-function passes (validating function bodies one at a time):

*Module-level passes.* Bounds checking, structural-limits checking, handle-and-identifier duplication checking, signature well-formedness, instruction-consistency checking (generic versus non-generic variant agreement), constant-pool validation, friend-declaration validation, ability-field-requirements checking on struct fields, recursive-data-definition cycle detection, and instantiation-loop detection. These passes mirror Sui-Move's module-level checks for the inherited subset and are extended where necessary to cover the Adamant-specific module-level metadata (the `b"adamant.mutability"` and `b"adamant.privacy"` entries per section 6.2.1.3, and the `b"adamant.allows_dynamic"` entry per section 6.2.1.6).

*Per-function passes.* Control-flow validation (CFG construction, branch-target validity, fall-through requirement on the last instruction, reducibility), operand-stack discipline (per-block stack-balance with full per-extension stack-effect knowledge from section 6.2.1.4), type safety (abstract interpretation of typed operand stack and locals across the CFG, with type-effect rules for each Adamant extension per section 6.2.1.4), locals safety (control-flow-sensitive availability tracking for local variables), reference safety (abstract borrow-graph tracking with reference-effect rules for `InvokeShielded` and `InvokeTransparent` per section 6.2.1.4 and for any extension whose signature includes references), and acquires-list checking (always trivial in Adamant since global storage is excluded per section 6.2.1.6 rule 5).

The verifier then runs the Adamant-specific rules per section 6.2.1.6.

**What the verifier proves.** A module that is accepted by the Adamant-native verifier satisfies, over the entire module body (Sui-base subset and Adamant extensions alike):

- *Type safety:* every operand on the stack at the consumption point of any instruction has the type that instruction expects.
- *Reference safety:* borrowed references do not outlive the values they reference; mutable references are not aliased; the borrow graph is consistent across the CFG.
- *Linearity:* values without the `copy` ability are not duplicated; values without the `drop` ability are not implicitly discarded.
- *Stack discipline:* the operand stack depth at every basic-block boundary is statically bounded; no instruction underflows the stack or causes runaway growth.
- *Control-flow integrity:* every branch target is a valid instruction within the function; the CFG is reducible.
- *Generic instantiation:* type arguments to generic instructions satisfy the abilities required by the generic parameters.
- *Friend visibility:* friend calls only reach declared friends.
- *Adamant-specific rules per section 6.2.1.6:* mutability metadata required, privacy annotation required on public functions, privacy consistency, no native functions, no global storage instructions, no dynamic dispatch (except with opt-in), privacy-circuit instructions in shielded context only, and bounded loops (per the §6.2.1.6 amendment, this is a runtime gas-budget property rather than a static check).

These guarantees apply uniformly to functions whether or not they contain Adamant extensions. There is no per-function dispatch to different verifier subsets; every function is checked by the full verifier in a single pass.

**Cross-validation against vendored Sui-Move.** The vendored Sui-Move `move-binary-format` and `move-bytecode-verifier` crates serve as a test-only cross-validation reference for the inherited Sui-base subset's semantics. A conforming Adamant implementation exercises Sui's verifier against pure-Sui modules (Adamant modules containing no extension instructions) at test time and confirms that Adamant's verifier reaches the same accept/reject decision — for any such module, the two implementations agree. This cross-validation is strictly a test-time property: it is not run at deployment, and the vendored crates do not appear in the production binary's dependency graph. The cross-validation is exercised by the implementation's test suite to confirm semantic parity with Sui for the inherited subset, surfacing any divergence at development time as a bug in either implementation.

The vendored Sui crates are pinned to the binary-format version specified in section 6.2.1.2 and may be refreshed independently of the Adamant verifier (subject to genesis-fixed binary-format compatibility). If a future Sui upstream change diverges from Adamant's behaviour for the inherited subset, the divergence is contained: Adamant's verifier is the binding implementation, and the vendored crates serve as a reference whose agreement is verified at test time. A vendor refresh that surfaces divergence is a development-time signal — it is not a consensus event, since the production-build pipeline never loads the vendored crates.

**Why fully Adamant-native rather than projection-based.** The architectural decision to verify the full Adamant superset directly, rather than projecting Adamant modules into a Sui-only form for Sui's verifier to check, follows from three considerations:

- *Empirical infeasibility of projection.* As noted in the parenthetical above, the `Nop` projection mechanism originally drafted does not work; 3 of Sui's 4 per-instruction passes reject the projection for non-trivial extension usage. Alternative projections (instruction stripping, per-extension multi-instruction substitution) reintroduce consensus-critical risk surfaces (offset rewriting on branch targets) that were ruled out in earlier investigation. There is no projection mechanism that simultaneously preserves Sui's per-instruction guarantees and avoids breaking branch targets.
- *Genesis-fixed posture.* Adamant's bytecode language and verifier rules are genesis-fixed (sections 6.2.1.4 and 6.2.1.6); once mainnet launches, the verifier's accept/reject decisions are part of consensus and cannot drift. A verifier that depends on Sui's vendored implementation in the deploy-time hot path inherits Sui's evolution as a potential consensus-drift surface — bumping the Sui vendor tag could in principle change which modules are accepted. An Adamant-native verifier removes this surface: Adamant's verifier is the binding implementation, and the vendored Sui crates serve as a reference for development and cross-validation only.
- *Audit surface.* Adamant's verifier is fully under Adamant's audit and maintenance, with consistent treatment of inherited-subset semantics and extension semantics. The "what does Sui's verifier do here" question never arises in the hot path; the verifier is one codebase under one set of eyes.

**Pipeline ordering.** A conforming Adamant deployment validator processes module bytes in the following order:

1. *Deserialize.* Parse the bytes into the Adamant module representation. Reject malformed bytes, unknown opcodes (including bytes outside both the Sui-base and Adamant-extension opcode ranges), or any structural violation of the binary format.
2. *Canonical-encoding round-trip.* Re-serialize the deserialized module and byte-compare against the input. Reject on any divergence.
3. *Module-level passes.* Run the Adamant-native module-level passes (bounds checking, signature well-formedness, etc.) on the deserialized module. Reject on any failure.
4. *Per-function passes.* For each function definition, run the Adamant-native per-function passes (control-flow, stack-usage, type-safety, locals-safety, reference-safety, acquires-list checking). Reject on any failure.
5. *Adamant-specific rules per section 6.2.1.6.* Run the eight rules enumerated in section 6.2.1.6 against the unmodified Adamant module representation. Reject on any failure.

A module is valid for deployment if and only if all five steps succeed. The order is fixed: each step's preconditions are established by the prior step's success, and the canonical-encoding check (step 2) precedes any verification work to ensure that the bytes the verifier examines are the canonical bytes the deployer submitted.

**Implementation note.** The Adamant-native deserializer, serializer, type definitions, helpers, and verifier passes are protocol-level concerns: a conforming implementation must reach the same accept/reject decision on every module-bytes input as the spec's pipeline, and the production-build dependency posture is fixed (no vendored Sui-Move crates in the production dependency graph; test-only, build-tooling-only, and CI-only dependencies are explicitly permitted). Internal representations, data-structure choices, and pass-orchestration details are implementation-discretionary, but both the externally observable accept/reject behaviour and the production-dependency posture are fixed. Two implementations that disagree on whether a given module-bytes input is valid for deployment are not both conforming, regardless of internal choices. The vendored Sui-Move crates are a cross-validation reference for the inherited subset and are exercised at test time; they are not part of the protocol-level specification and cannot appear in conforming production builds.

### 6.2.2 Execution model

When a transaction is executed by the AVM, the following sequence occurs:

1. **Authorisation.** The transaction's authorisation logic is run (section 4). If invalid, execution aborts.

2. **Object loading.** All objects referenced by the transaction are loaded from chain state. The transaction declares its read-set and write-set in advance; the loader validates that the transaction touches no objects outside its declared sets.

3. **Type checking.** The bytecode is verified against the declared types of loaded objects.

4. **Gas budgeting.** The transaction's gas budget (specified by the user, paid in advance) is checked against the protocol's minimum requirements.

5. **Execution.** Bytecode runs to completion or until gas is exhausted. State changes are accumulated in a transaction-local buffer; chain state is not mutated until execution succeeds.

6. **Privacy proof generation.** For shielded transactions, a Halo 2 proof is generated attesting to the correctness of the execution without revealing the shielded inputs or state. For transparent transactions, no proof is required.

7. **Commit or abort.** If execution succeeded and (for shielded transactions) the proof verifies, state changes are committed: object versions increment, ownership transfers apply, new objects are created, destroyed objects are removed. If execution failed, all state changes are discarded except for the gas charged.

This model is per-transaction. Parallel execution across transactions is the next subsection.

### 6.2.3 Parallel execution

The protocol exploits the causal-independence property of the object model (section 5.2.1) to execute many transactions in parallel. The mechanism is **deterministic, declared parallelism**: each transaction declares its read-set and write-set; the scheduler partitions transactions into groups whose declared sets do not overlap; each group runs in parallel.

**Scheduler algorithm (high level).** Given a batch of transactions to execute:

1. Compute the conflict graph: nodes are transactions; edges connect transactions whose read/write sets overlap.
2. Compute a graph colouring: transactions of the same colour have no edges, hence no conflicts.
3. Execute all transactions of the same colour in parallel on available cores.
4. Once a colour completes, proceed to the next colour.
5. Across colours, ordering follows the consensus order from section 8.

This is a deterministic version of the Block-STM algorithm used by Aptos and Sui, with the optimisation that conflicts are detected statically (from declared sets) rather than discovered optimistically at runtime. Static detection is possible because Adamant Move requires explicit declaration of read/write sets; this is a deliberate language design choice that pays off at execution.

**Throughput properties.** For typical workloads, in which the vast majority of transactions touch disjoint object sets, the conflict graph has very few edges and most transactions run in the first colour. Empirically (extrapolating from published Sui and Aptos benchmarks), this translates to per-validator throughput of 100,000+ transactions per second per CPU core, scaling roughly linearly to the number of cores used. The 200,000 TPS target in Principle IV is achievable on a 4–8 core validator at realistic conflict rates.

**Conflict handling.** When two transactions conflict, the consensus order (section 8) determines which executes first. The losing transaction is re-executed against the post-state of the winner; if the re-execution succeeds, both commit; if it fails (for example, the winner consumed a resource that the loser also needed), the loser aborts with a clear error and its gas is charged against the user's account.

### 6.2.4 Determinism

The AVM is deterministic: two executions of the same transaction against the same state produce identical results. This is essential for consensus: validators must agree on the outcome of every transaction without communicating.

Sources of nondeterminism that Adamant Move and the AVM eliminate:

- **No floating-point arithmetic.** All numeric operations are over fixed-precision integers.
- **No system time access.** Functions cannot query wall-clock time. The chain provides a "consensus time" derived from the consensus mechanism (section 8) which is deterministic across all validators.
- **No randomness from runtime sources.** When randomness is needed, it comes from the consensus VRF (section 8), which is deterministic given the chain state.
- **No I/O.** The AVM cannot make network requests, read files, or interact with anything outside the chain state.
- **Bounded loops only.** All loops must have statically-bounded iteration counts or run within a gas budget that bounds them dynamically.
- **No undefined behaviour.** All operations have specified behaviour for all inputs; there is no equivalent of C's "undefined behaviour" that compilers may exploit.

These constraints are familiar from other smart-contract VMs and are necessary for the correctness of the consensus mechanism. The cost is that some classes of computation cannot be expressed in Adamant Move; this is acceptable.

## 6.3 Resource accounting (gas)

Computation on Adamant is metered. Every operation has a gas cost; transactions specify a gas budget; the budget is charged regardless of whether the transaction succeeds. This prevents denial-of-service attacks and allocates a finite computational resource fairly.

### 6.3.1 Multi-dimensional gas

Adamant uses multi-dimensional gas accounting, separating distinct resources rather than collapsing them into a single number. The dimensions are:

1. **Computation.** CPU cycles consumed by bytecode execution. Charged per instruction class, with weights calibrated to actual hardware costs.

2. **State storage.** Bytes added to active state. Charged per byte at object creation and at object growth.

3. **State rent prepayment.** When an object is created, an amount of rent (section 5.6) must be prepaid. This is a separate dimension from storage to allow per-byte storage and per-byte-second rent to be priced independently.

4. **Bandwidth.** Bytes transmitted by validators when propagating the transaction. Charged per byte at submission.

5. **Proof verification.** CPU cost of verifying zero-knowledge proofs attached to shielded transactions. Charged per proof.

6. **Proof generation (optional).** CPU cost of generating zero-knowledge proofs, if outsourced to a prover market (section 7). Charged per proof when used.

Each dimension has its own price (in ADM) set per epoch by the EIP-1559-style mechanism specified in section 10. A transaction's total fee is the sum of its consumption across dimensions, each multiplied by the relevant price.

**Why multi-dimensional.** The cost of a simple transfer is dominated by computation and bandwidth; the cost of creating a large data object is dominated by storage; the cost of a complex shielded operation is dominated by proof verification. Pricing these as a single "gas" number, as Ethereum does, mis-allocates resources: simple transfers subsidise heavy contracts, and the chain's bottleneck shifts unpredictably between resources. Multi-dimensional accounting prices each resource at its actual marginal cost.

### 6.3.2 Gas costs are fixed at genesis

The gas costs of individual instructions are part of the consensus rules and are fixed at genesis. They cannot be modified by any on-chain mechanism. Changes require a hard fork (section 11).

This is consistent with Principle I (credible neutrality) but represents a real constraint. If, post-genesis, an instruction is found to be under-priced (allowing denial-of-service attacks) or over-priced (deterring legitimate use), the protocol cannot be patched without coordinating a hard fork. The genesis gas table must therefore be calibrated carefully against published benchmarks before launch.

The exception is the *prices* — the multipliers from gas units to ADM. Prices are determined per-epoch by the EIP-1559-style mechanism in section 10, which targets a specific block-fullness. This is not governance; it is a feedback loop with parameters fixed at genesis.

### 6.3.3 Failed transactions are charged

A transaction that fails partway through execution is charged for the gas it consumed up to the point of failure, plus a small minimum fee. This prevents adversaries from submitting failing transactions for free.

The exception is authorisation failure: if a transaction's authorisation logic (section 4) returns invalid, the transaction is rejected at the mempool layer and never executed. No gas is charged because no execution occurred.

### 6.3.4 Sponsored transactions

The smart-account model (section 4) allows validation logic to specify that fees are paid by an account other than the transaction submitter. This enables:

- **Application-sponsored transactions.** A dapp pays the gas for its users' interactions, removing a key onboarding friction.
- **Paymaster contracts.** A specialised contract pays gas for specified categories of transactions, charging users in another currency or off-chain.
- **Free-tier sponsorship.** A protocol-deployed contract pays gas for users below a usage threshold, funded by some other mechanism (advertisement-free model, philanthropic funding, etc.).

Sponsored transactions are not a special case in the protocol; they are a natural consequence of validation logic being arbitrary code. The "fee payer" of a transaction is whichever account the validation logic specifies — typically, but not necessarily, the transaction submitter.

## 6.4 Module deployment and upgrades

Smart contracts on Adamant are organised into *modules*, the same unit of code organisation as in standard Move. A module contains type definitions and function definitions; modules are deployed to the chain as Adamant Move bytecode.

### 6.4.1 Deployment

Module deployment is a transaction whose effect is to create a new `Module` object on the chain. The `Module` object's `mutability` field is the module's declared mutability (from the `#[mutability(...)]` annotation, section 6.1.2). The module's bytecode is stored in the `contents` field.

After deployment, contracts and other modules can reference the deployed module by its `ObjectId`, invoke its public functions, and read its public types.

### 6.4.2 Upgrade

A module upgrade is a transaction that submits new bytecode to replace the existing bytecode of a module. Whether the upgrade succeeds depends on the module's mutability:

- `Immutable` modules cannot be upgraded. Upgrade transactions targeting them are rejected by consensus.
- `OwnerUpgradeable` modules can be upgraded by a transaction signed by the owner.
- `VoteUpgradeable` modules can be upgraded after a successful vote, with the upgrade applied after the execution delay.
- `UpgradeableUntilFrozen` modules can be upgraded by the owner until the freeze operation is called, after which they behave as `Immutable`.
- `Custom` modules can be upgraded subject to the validator object's rules.

### 6.4.3 Compatibility constraints on upgrades

A module upgrade is required to be *compatible* with the previous version, in a specific technical sense: types defined by the module that are referenced by other modules cannot be removed or have their layout changed. Adding new types, new functions, or extending existing functions in backward-compatible ways is permitted.

**Privacy annotations are part of the public API contract.** The privacy annotation on a public function (per section 6.2.1.3) is upgrade-immutable: an upgrade may not change a public function's annotation from `#[transparent]` to `#[shielded]` or vice versa. This is enforced at upgrade time alongside the existing compatibility checks; an upgrade attempting to change a public function's privacy annotation is rejected.

This constraint exists because dependent modules may have been deployed against the original privacy annotation — a `#[shielded]` caller in another module that linked against an upgraded function expecting it to remain `#[shielded]` should not silently find itself calling a `#[transparent]` implementation after the upgrade. Privacy mode is a fundamental property of how a function interacts with the rest of the chain, and changing it across upgrades would invalidate the static deploy-time guarantees that dependent modules rely on (per section 6.2.1.6 rule 3). Internal (non-public) functions may change privacy mode across upgrades freely; only public functions are constrained, since only public functions are part of the cross-module API surface.

This constraint exists to prevent silent breakage of dependent contracts. If module A defines type `T` and module B holds a value of type `T`, an upgrade to module A that removes `T` would render module B's value un-interpretable. The compiler and the chain enforce this constraint at upgrade time.

For cases where breaking changes are desired, the standard pattern is to deploy a new module (with a new `ObjectId`) and migrate users explicitly.

## 6.5 Standard library

The protocol provides a standard library of modules, deployed at genesis with `Immutable` mutability. The standard library includes:

- `adamant::primitives` — basic types (vectors, options, strings, etc.) and operations
- `adamant::object` — object manipulation primitives
- `adamant::address` — address arithmetic and validation
- `adamant::hash` — SHA-3 and BLAKE3 wrappers
- `adamant::signature` — Ed25519 and ML-DSA verification
- `adamant::privacy` — shielded execution primitives
- `adamant::token` — fungible token reference implementation
- `adamant::nft` — non-fungible token reference implementation
- `adamant::governance` — vote-based mutability helpers
- `adamant::recovery` — social-recovery helpers for accounts

Modules in the standard library are accessible from any contract without separate deployment. They are `Immutable` and cannot be modified post-genesis. A future hard fork may extend the standard library; existing standard-library modules are permanent.

The standard library is deliberately conservative. It provides the primitives applications need without prescribing application architectures. Higher-level patterns (decentralised exchange logic, lending protocols, identity systems, etc.) are expected to be implemented as user-deployed modules, not bundled into the standard library.

## 6.6 Verification and the Move Prover

The Move language was designed alongside the **Move Prover**, a static verification tool that checks contracts against formal specifications. Adamant Move inherits the Move Prover; specifications written in the Move Prover specification language are checked against contracts at compile time.

The Move Prover's contribution is the ability to prove non-trivial properties of contracts: "this contract never allows the total token supply to exceed X", "this lending protocol never allows under-collateralised positions", "this voting contract never allows double-voting". These are exactly the properties that have, on other chains, been violated by deployed contracts with catastrophic consequences.

The protocol does not require contracts to be Prover-verified; it does, however, strongly recommend it for any contract holding significant value. Reference wallets `SHOULD` surface verification status to users when displaying contracts: "this contract has been formally verified for the property [X]" is a meaningfully different trust signal than "this contract compiled without errors".

## 6.7 Worked example: continuing the token

Continuing the worked example from section 5.8, here is the structure of a fungible-token module in Adamant Move:

```move
#[mutability(immutable)]
module 0xCOFFEE::example_token {
    use adamant::object;
    use adamant::token;

    public struct ExampleToken has key, store {
        id: object::ObjectId,
        balance: u64,
    }

    public struct TokenSupply has key {
        id: object::ObjectId,
        total: u64,
        max_supply: u64,
    }

    #[shielded]
    public fun transfer(
        from: &mut ExampleToken,
        to: &mut ExampleToken,
        amount: u64,
    ) {
        // Linear types ensure 'amount' is accounted for exactly:
        // it leaves 'from' and arrives at 'to'.
        from.balance = from.balance - amount;
        to.balance = to.balance + amount;
        // The compiler emits range-proof and balance-conservation
        // circuit witnesses automatically, because the function is
        // marked #[shielded].
    }

    #[transparent]
    public fun supply(supply: &TokenSupply): u64 {
        supply.total
    }

    // ... mint, burn, etc.
}
```

A few features worth observing:

- The mutability is declared `Immutable` at the module level. The module's code cannot be changed after deployment. Users interacting with the token can rely on its current rules forever.
- The `transfer` function is `#[shielded]`. The compiler automatically generates the zero-knowledge circuit witness; the developer writes ordinary code.
- The linear type system ensures `amount` is correctly accounted for. Code that "forgets" to update `to.balance` after subtracting from `from.balance` does not compile.
- The function body is short because the protocol provides the cryptographic machinery. The contract author writes business logic; the protocol handles cryptography.

This worked example will be revisited in section 7 (Privacy Layer), which specifies the cryptographic mechanisms underlying `#[shielded]` functions.
