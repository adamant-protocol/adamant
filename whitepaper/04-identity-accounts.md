# 4. Identity & Accounts

This section specifies how identity is represented on Adamant: how accounts are constructed, how keys authorise transactions, how users delegate visibility through view keys, and how recovery from key loss is handled. The design follows directly from the principles in section 2: privacy by default (II), permissionless participation (VII), and the cryptographic primitives in section 3.

The protocol's account model is uncompromisingly modern: **every account is a smart account from genesis**. There is no distinction between "externally-owned accounts" and "contract accounts" as found in Ethereum. There is no special category of account with privileged validation logic. There is no account type that requires migration to access account-abstraction features. Account abstraction is not a feature layered on top of the base protocol; it is the only model the base protocol supports.

This is the model used by zkSync Era, StarkNet, and Aptos, and it is the only sensible model for a chain designed in 2026. ERC-4337-style add-on architectures exist on Ethereum because Ethereum's account model was fixed in 2015 and cannot be changed without breaking compatibility. Adamant has no such constraint and uses the cleaner design.

## 4.1 What an account is

An Adamant account is an on-chain object (objects are specified in section 5) with the following minimum properties:

1. **An address.** A 32-byte identifier derived deterministically from the account's initial public key material at creation time. Addresses are stable: an account's address never changes, even if its keys are rotated.

2. **Authentication state.** The set of cryptographic public keys, validation rules, and other authentication parameters the account uses to determine whether a given transaction is authorised.

3. **Validation logic.** The function that, given a candidate transaction and the account's authentication state, returns either *valid* or *invalid*. This logic is expressed in the protocol's smart-contract language (section 6) and is invoked for every transaction submitted under this account's authority.

4. **Mutability declaration.** The account's mutability policy, declared at creation, governing whether and how the validation logic and authentication state may change. Mutability is one of the standard policies described in section 2.5 (`IMMUTABLE`, `OWNER_UPGRADEABLE`, etc.).

5. **State.** Any account-specific data the account needs to maintain. By default this includes a transaction nonce counter (to prevent replay) and a sequence of any objects the account holds. Accounts may declare additional state at creation.

6. **View key set (optional).** A set of view keys that allow specified third parties to observe the account's transaction history without granting transaction-authorisation power. Specified in detail in section 4.4.

This list is the minimum. Accounts may declare additional fields at creation, subject to the validation rules of the smart-contract language.

## 4.2 Account creation

Accounts are created on Adamant by submitting an account-creation transaction. The transaction specifies:

- The initial authentication state (public key(s), validation rules)
- The validation logic (the smart-contract code that determines authorisation)
- The mutability declaration
- Any initial state values
- An optional human-readable label (no on-chain semantics; for wallet display only)

The address of the new account is computed as `SHA3-256(domain_tag || creation_tx_hash || creator_address || index)` where `index` is a per-creator counter ensuring uniqueness. Accounts are not created at "well-known" addresses; there is no equivalent of Ethereum's `CREATE2` predictable address mechanism, because the protocol's privacy model makes pre-funding of unfunded addresses unnecessary.

**No account creation gating.** Account creation is permissionless. The cost of creating an account is paid in the standard fee mechanism (section 10). There is no minimum balance, no whitelist, and no creator-specific privileges.

**No precompiled accounts.** The protocol contains no built-in accounts with privileged behaviour. There is no equivalent of Ethereum's precompiled contracts (`0x1` through `0x9`) or system contracts. Every account on the chain is created through the same mechanism described above. This is required by Principle I.

## 4.3 Authentication

When a transaction is submitted under an account's authority, the protocol invokes the account's validation logic with the transaction's contents as input. The validation logic returns *valid* or *invalid*. *Valid* causes the transaction to be admitted to the mempool and processed; *invalid* causes it to be rejected before any state change.

The validation logic is arbitrary smart-contract code, subject only to the resource limits described in section 6. This is the substance of "smart accounts": validation is *programmable*. Standard validation patterns supported by reference implementations include:

### 4.3.1 Single-signature validation

The simplest pattern: the account holds a single Ed25519 or ML-DSA public key, and a transaction is valid if and only if it carries a signature from the corresponding secret key over the transaction's canonical encoding.

This pattern is the default for new user accounts created by reference wallets. It approximates the user experience of legacy externally-owned accounts on other chains while remaining smart-account-native.

### 4.3.2 Dual-signature validation (classical + post-quantum)

The protocol's recommended pattern for accounts intending to hold significant value over long timescales: the account holds both an Ed25519 key and an ML-DSA key, and a transaction is valid only if it carries valid signatures from both.

This pattern provides defence in depth. An adversary capable of compromising Ed25519 (for example, a future quantum adversary) cannot forge transactions because they would also need to compromise ML-DSA. An adversary capable of compromising ML-DSA (for example, an unforeseen lattice attack) cannot forge transactions because they would also need to compromise Ed25519. The account is secure unless *both* schemes are simultaneously broken.

The cost is that signing requires both keys to be available, and the signature itself is larger (Ed25519 is 64 bytes, ML-DSA-65 is 3293 bytes). For long-term storage of value, this is an acceptable trade-off.

### 4.3.3 Threshold-signature validation

The account holds N public keys and a threshold k. A transaction is valid if at least k of the N keys have signed it. This is the standard multi-signature pattern, expressed natively in the smart-account model rather than requiring a separate multisig contract.

Common configurations: 2-of-3 (a typical personal multi-device setup), 3-of-5 (a typical institutional setup), m-of-n where the keys are held by a board of trustees.

### 4.3.4 Time-locked validation

The account's validation logic may incorporate time-based constraints. Examples:

- **Spending limits.** A transaction transferring more than X tokens within a Y-second window requires additional signatures.
- **Cooling periods.** Certain operations require a delay between submission and execution, during which they may be cancelled.
- **Beneficiary access.** Specific keys gain transaction authority only after the account has been inactive for a specified period (a dead-man's-switch pattern, useful for inheritance arrangements).

### 4.3.5 Session keys

A session key is a secondary key authorised to submit a restricted class of transactions on behalf of the account, typically time-bounded and scope-restricted. Example: an account's primary key (held offline) authorises a session key to make transactions of value less than X with a specific application contract for the next 24 hours. The application can then operate without prompting the user for signatures every transaction, while the user retains protection against runaway authority.

Session keys are a natural use of the smart-account model: the validation logic specifies that signatures from the session key are accepted only when the transaction matches the session key's restrictions. This is the same pattern used by StarkNet's session keys (deployed in production for game applications such as Cartridge's Flippy Flop, October 2024) and by various account-abstraction systems on Ethereum.

### 4.3.6 Custom validation

The above patterns are illustrative, not exhaustive. The validation logic can implement any logic expressible in the smart-contract language: passkey signatures (WebAuthn), threshold-encrypted shares, social-recovery rules, biometric-gated transactions (via attested device signatures), and arbitrary combinations thereof. The protocol does not prescribe what validation looks like; it provides the framework within which any validation policy can be expressed.

## 4.4 View keys and selective disclosure

Adamant transactions are private by default (Principle II). The account holder, by default, is the only party who can observe their account's transaction history in clear form. This is the protocol's security baseline.

But many legitimate use cases require selective disclosure: a user proving their tax obligations to a government, a business proving its solvency to an auditor, an exchange proving its reserve composition to its customers. The view-key mechanism enables these use cases without compromising default privacy.

### 4.4.1 What a view key is

A view key is a cryptographic key that grants the holder the ability to *observe* an account's transactions in clear form, but not to *authorise* new transactions. It is a one-way trapdoor: a user can derive view-key access from their full account access, but a view-key holder cannot derive transaction-authorisation access from a view key.

Concretely: a user account holds a master seed. The master seed deterministically generates two distinct keypairs: the *spending key*, which is used in transaction validation, and the *viewing key*, which is used to decrypt the user's own transactions on the chain. The spending key cannot be derived from the viewing key. The user can disclose the viewing key (or sub-keys derived from it) to any third party without granting them spending power.

This construction follows the design used in Zcash since Sapling (2018) and refined in subsequent shielded-pool protocols. It is a well-understood pattern with substantial deployment evidence.

### 4.4.2 Sub-view-keys for granular disclosure

The viewing key is hierarchically structured. A user can derive sub-keys that grant visibility into restricted subsets of their transactions. Examples:

- **Time-bounded view key.** Visibility into transactions occurring between dates D1 and D2 only, useful for annual tax filings without exposing other periods.
- **Counterparty-bounded view key.** Visibility into transactions involving a specific counterparty only, useful for proving a specific commercial relationship without exposing unrelated activity.
- **Amount-bounded view key.** Visibility into transactions exceeding a specified amount only, useful for high-value-transaction reporting requirements.

Sub-view-key derivation is specified cryptographically by section 7 (Privacy Layer); from the user's perspective, wallets expose this as "create an audit key for [specific use]" with the relevant parameters.

### 4.4.3 View keys are not surveillance

The protocol's view-key mechanism is fundamentally different from surveillance-friendly architectures (such as backdoor decryption, key escrow, or "lawful access" mechanisms). The differences:

1. **User-controlled disclosure.** Only the account holder can issue a view key. The protocol contains no mechanism by which any other party — not validators, not the original implementers, not governments — can compel decryption against the user's will.

2. **Granular and revocable.** The user controls the scope of disclosure (which transactions, over which period) and can stop deriving new sub-keys at any time. Already-issued sub-keys reveal only the data they were authorised to reveal; they cannot be retroactively expanded.

3. **No technical means of compulsion.** The protocol does not include any mechanism for a third party to demand a view key cryptographically. A user who refuses to disclose simply does not disclose; the protocol provides no means of override.

The view-key mechanism is therefore a tool for the user, available when the user chooses to use it, not an infrastructure for compelled disclosure.

## 4.5 Key rotation

A user `MUST` be able to rotate the keys associated with their account without changing the account's address or losing access to their state.

**Mechanism.** Key rotation is performed by submitting a transaction signed under the account's *current* validation logic that updates the authentication state to a new set of keys. The transaction has the same structure as any other transaction; the only difference is its target (the account's own authentication state) and its effect (replacing keys).

**Constraints by mutability declaration.** Whether key rotation is permitted at all, and under what conditions, depends on the account's mutability declaration (section 2.5):

- `IMMUTABLE` accounts: rotation is forbidden. The account's keys are fixed at creation.
- `OWNER_UPGRADEABLE` accounts: rotation requires a signature from the designated owner key.
- `VOTE_UPGRADEABLE` accounts: rotation requires a vote from the designated token holders meeting the specified threshold.
- `UPGRADEABLE_UNTIL_FROZEN` accounts: rotation is permitted until the account is frozen, then forbidden.
- `CUSTOM` accounts: rotation follows the rules declared at account creation.

**Rotation is not migration.** Rotating keys is distinct from migrating to a different account. Rotation preserves the account's address, state, holdings, view keys, and transaction history. The account is the same account; only the keys that authorise it have changed.

**Why rotation matters.** Long-lived accounts will need to rotate keys for many reasons: routine key hygiene, response to suspected compromise, transition to post-quantum keys as cryptographic best practice evolves, transition between hardware-wallet generations, and changes in the user's threat model. The protocol makes this a first-class operation rather than requiring users to migrate to a new account.

## 4.6 Recovery

Key loss — losing the ability to sign transactions because the secret key has been lost, destroyed, or rendered inaccessible — is the single most common failure mode in cryptocurrency. The protocol does not solve this problem at the cryptographic layer; it provides building blocks that allow users to construct recovery solutions appropriate to their threat model.

### 4.6.1 The protocol provides no built-in recovery

There is no protocol-level mechanism by which a lost key can be replaced without authority from the existing account. There is no foundation that can issue replacement keys. There are no validators with the authority to override an account. The protocol's commitment to credible neutrality (Principle I) precludes any such mechanism.

A user who creates an `IMMUTABLE` single-signature account and loses the key has lost the account. The protocol does not provide a fallback. This is a property of the security model, not an oversight.

### 4.6.2 What the protocol enables

The smart-account model enables users to construct recovery mechanisms appropriate to their needs. The most common patterns:

**Social recovery.** The account is configured such that a quorum of designated "guardians" — friends, family members, multiple devices — can collectively rotate the account's keys, even without the original key. Each guardian holds a key that, in isolation, has no power; only when k of n guardians cooperate can a new authorisation key be installed. This is the model used by Argent (deployed since 2018) and the Ethereum Foundation has explicitly endorsed it as the recommended recovery pattern. The protocol supports this natively through the smart-account validation model.

**Time-locked recovery.** The account is configured such that a recovery key gains the ability to rotate the account's keys, but only after a delay (e.g. seven days) during which the account holder can cancel the recovery using their primary key. An adversary who steals the recovery key cannot use it immediately; the legitimate holder has a window to detect and abort. This is a useful pattern when the recovery key is held by an institution (a law firm, a digital-estate service) whose attack surface is non-zero.

**Multi-device redundancy.** The account is configured as a 2-of-3 threshold with keys held on three distinct devices (phone, laptop, hardware wallet). Loss of any one device does not compromise the account; loss of two simultaneously is required.

**Inheritance arrangements.** The account is configured such that, after a specified period of inactivity (no signed transactions for, say, twelve months), beneficiary keys gain transaction authority. The account holder can defeat this by signing any transaction during the inactivity period. This is a dead-man's-switch pattern useful for digital inheritance.

**Hardware-secured recovery.** Recovery keys are held in hardware security modules, secure elements, or third-party custodial services. The protocol does not specify the hardware; it specifies that the validation logic can incorporate signatures from hardware-attested keys.

The protocol's role is to provide the framework. The user's role is to choose a configuration appropriate to their needs and to communicate with their guardians, beneficiaries, or service providers about the implications.

### 4.6.3 Wallet defaults

Reference wallets `SHOULD` strongly default new user accounts to a recovery-enabled configuration. The exact default is wallet-specific, but the principle is that a user creating their first account `SHOULD NOT` be defaulted to an `IMMUTABLE` single-signature configuration without explicit informed consent. The risk of catastrophic loss to inexperienced users is too high to justify defaults that leave them no recovery path.

A recommended default for new user accounts is: `OWNER_UPGRADEABLE` with social recovery, requiring 2-of-3 guardians (one of which may be the user's own backup device, two of which are external). This default provides reasonable protection against routine key loss while preserving full user control.

## 4.7 Privacy of accounts

By default, account addresses are not directly observable from transaction data. The transaction format (specified in section 5) does not include cleartext sender or recipient addresses; instead, it references shielded notes whose ownership is verifiable only by the parties holding the relevant view keys.

This means that account-level analysis ("how many transactions has this address sent?") is not possible from the chain alone, by design. An observer can see *that* transactions occurred (the encrypted envelope and the proof that it is well-formed) but not *which addresses* were involved.

**Optional transparency.** A user may submit a transaction in transparent form, exposing sender, recipient, and amount in cleartext. This is useful for specific applications: public charitable donations, public bounty payments, transparent governance votes (when those occur off-protocol, as Adamant has no on-chain governance), and similar contexts. Transparency is a per-transaction choice, not a chain-wide default, and not a property of the account itself.

**Account discoverability.** Because addresses are not exposed by default, accounts are *not* easily discoverable from chain data. This is the inverse of the assumption built into chains where every transaction exposes its participants. The implication for user-experience: an account "exists" as soon as it is created, but it is not visible to third parties unless the holder discloses its address (typically via off-chain channels: paste an address into a chat, scan a QR code, share via a payment-request URI).

Reference wallets handle address sharing through the standard mechanisms used by privacy chains: stealth addresses, shareable payment requests, or QR-encoded one-time identifiers. Section 7 specifies the cryptographic basis for stealth addresses; section 4 establishes only that account addresses are not assumed to be public.

## 4.8 Worked example: a typical user account

To make the foregoing concrete, here is the configuration of a typical personal account created by a reference wallet for a new user:

- **Mutability:** `OWNER_UPGRADEABLE`
- **Authentication:** dual-signature (Ed25519 + ML-DSA), with the keys derived from the user's recovery seed phrase
- **Recovery:** social recovery configured with three guardians, requiring two to authorise a key rotation
- **View keys:** generated and stored locally; not yet shared with any third party
- **Session keys:** none initially; added per-application as the user grants permissions
- **Spending limits:** $10,000 USD-equivalent per 24-hour period without additional signatures (configurable)
- **Transaction privacy:** shielded by default; transparency available per-transaction

This configuration trades some complexity (the user needs three guardians) for a substantial improvement in security relative to a legacy single-key account. It supports key rotation without migration, recovery from key loss without protocol-level intervention, and audit cooperation through view-key derivation as needed. It is post-quantum-secure (via the ML-DSA component) and compatible with the encrypted-mempool architecture.

Reference wallets `SHOULD` make this configuration achievable in approximately the same number of user actions as creating a legacy single-key account elsewhere. The complexity is the wallet's responsibility, not the user's.

## 4.9 Account-level fees and gas

This section briefly anticipates section 10 (Economics & Incentives). Account-related operations — creation, key rotation, validation logic invocation — are subject to the protocol's fee mechanism. The fee for account creation is paid by the creator. Validation logic invocation (which occurs for every transaction the account submits) is paid by whichever party the validation logic specifies as fee-payer; this enables sponsored transactions, where an application or paymaster pays fees on behalf of the user.

Section 10 specifies fee structure in detail. The note here is that the smart-account model permits fee abstraction natively: the question of "who pays" is part of the validation logic, not a separate concept.
