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
- Bytecode format (Adamant Move bytecode is a strict superset of standard Move bytecode, with the additional protocol-specific instructions documented in subsection 6.3)
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

AVM bytecode is a register-based instruction set with the following classes of instructions:

- **Stack and register operations.** Move values, copy primitive values, swap, drop.
- **Arithmetic and logical operations.** Integer arithmetic (with overflow checks by default), bitwise operations, comparison.
- **Object operations.** Read object field, write object field, transfer ownership, create object, destroy object.
- **Control flow.** Conditional branches, function calls, loops with bounded iteration.
- **Privacy operations.** Invoke shielded function, invoke transparent function, generate proof, verify proof, release sub-view-key.
- **Cryptographic primitives.** Hash, signature verification, KZG operations, Halo 2 circuit invocation.
- **Resource operations.** Charge gas, query remaining gas, raise out-of-gas error.

The instruction set is finite and frozen at genesis. New instructions cannot be added without a hard fork (section 11).

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
