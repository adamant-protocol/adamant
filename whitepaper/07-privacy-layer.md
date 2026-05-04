# 7. Privacy Layer

This section specifies how Adamant achieves privacy by default. It is the longest and most cryptographically dense section in this whitepaper, because privacy that is genuinely usable — private by default, programmable, auditable when the user chooses, and resistant to deanonymisation through chain analysis — requires substantial cryptographic machinery.

The section builds on section 3 (cryptographic primitives), section 4 (account model and view keys), section 5 (object model), and section 6 (Adamant Move's `#[shielded]` annotation). It specifies:

1. The note model: how value is represented privately on the chain
2. Stealth addresses: how recipient identities are hidden
3. Shielded execution circuits: how Halo 2 proofs attest to correct shielded computation
4. View keys and selective disclosure: the cryptographic basis of section 4.4
5. The shielded pool: the global anonymity set
6. Encrypted memos: how parties communicate transaction context privately
7. Prover markets: the optional outsourcing of proof generation
8. Compliance considerations and threat boundaries

The design follows from Principle II (privacy by default), and it is designed to interact cleanly with Principle I (credible neutrality) and Principle IV (performance). Where these come into tension, the priority order in section 2.8 governs.

## 7.1 The note model

The fundamental unit of shielded value on Adamant is the **note**: a cryptographic commitment to a value held by a specified recipient under specified conditions. Notes are conceptually similar to Zcash Sapling/Orchard notes and to Aztec's notes, with adaptations for Adamant's object model.

A note is a tuple:

```
Note {
    value:        u64,           // the amount, in the smallest unit
    asset_type:   TypeId,        // identifies the type of asset (e.g. ADM, a token type)
    recipient:    StealthAddress, // see section 7.2
    randomness:   [u8; 32],      // sampled per note; ensures uncorrelatable commitments
    metadata:     NoteMetadata,  // application-specific data
}
```

A note never appears on the chain in cleartext. What appears on the chain is the note's **commitment**, computed as:

```
commitment = Poseidon(value || asset_type || recipient || randomness || metadata_hash)
```

The commitment is 256 bits and reveals nothing about its inputs. Two notes with the same `value`, `asset_type`, and `recipient` but different `randomness` values produce uncorrelated commitments.

### 7.1.1 Note states

Notes have three possible states:

1. **Created** — the commitment exists in the global note commitment tree, but the note has not been spent.
2. **Spent** — the note's nullifier has been published, indicating that the note has been consumed by some transaction. The note's commitment remains in the tree (commitments are append-only) but the nullifier prevents double-spending.
3. **Discoverable** — the note's owner has access to it via their view key but has not yet spent it. This is a property of view-key holders, not a global state.

### 7.1.2 Nullifiers

A **nullifier** is a 256-bit value uniquely derived from a note and its owner's secret key. It is published to the chain when the note is spent, and the chain rejects any future transaction that publishes the same nullifier.

Nullifier construction:

```
nullifier = Poseidon(domain_tag || nullifier_key || note_commitment || position_in_tree)
```

Where:
- `nullifier_key` is a key derived from the owner's spending key (specifically: `nullifier_key = Poseidon(domain || spending_key)`)
- `position_in_tree` is the note's leaf index in the global commitment tree

This construction has critical properties:

- **Unlinkability.** A nullifier reveals nothing about the note it nullifies — neither value, recipient, nor commitment. To an observer, a published nullifier is a random 256-bit value.
- **Uniqueness.** Each note has exactly one valid nullifier. An attacker who tries to spend the same note twice must produce the same nullifier; the chain rejects the duplicate.
- **Unforgeability.** Producing the correct nullifier requires the spending key. Without it, computing the nullifier is intractable.

### 7.1.3 The note commitment tree

All note commitments ever created on Adamant live in a single append-only Merkle tree, the **global note commitment tree** (GNCT). The tree has a fixed depth of 64, allowing 2^64 notes — sufficient for the chain's projected lifetime.

Tree properties:

- **Append-only.** Once a commitment is added, it cannot be removed or modified. This is essential to the privacy model: removing commitments would create deanonymisation opportunities.
- **Per-shielded-transaction Merkle proof.** A transaction spending a note proves, via a Merkle path, that the note's commitment is in the tree. The proof reveals only the path's hash chain, not which specific commitment is referenced. This is the basis of the protocol's anonymity set.
- **Anonymity set = entire tree.** Every shielded spend is indistinguishable from spending any other note in the tree, because the Merkle proof reveals only that *some* commitment in the tree is being spent. The anonymity set grows with the chain's history.
- **Recent-roots window.** Validators retain Merkle roots of the GNCT for the most recent 100 epochs (approximately 1 hour at 36-second epochs). Spends prove against any of these roots, allowing wallets to spend notes without re-syncing the latest tree state on every transaction.

The tree is implemented using the Pedersen-hashed Merkle construction with Poseidon hashing for in-circuit efficiency.

### 7.1.4 Comparison with Zcash and Aztec

Adamant's note model is closest to Zcash Orchard (the current generation of Zcash shielded notes), with two adaptations:

1. **Asset diversity.** Adamant notes carry an `asset_type` field, allowing many distinct assets (tokens, NFT-like objects, etc.) to share the global anonymity set. Zcash's Orchard pool is single-asset (ZEC only); Adamant's design follows Aztec's multi-asset approach.

2. **Programmable metadata.** Adamant notes carry application-specific metadata, allowing contracts to attach arbitrary data to notes (e.g. a vesting schedule, an unlock condition, an attached message hash). The metadata is committed in the note commitment but visible only to view-key holders.

These adaptations preserve Zcash's strong privacy properties while extending the model to support programmable shielded contracts.

## 7.2 Stealth addresses

A **stealth address** is a one-time-use address derived from a recipient's long-term identity such that observers cannot link multiple notes destined for the same recipient.

### 7.2.1 The problem stealth addresses solve

Without stealth addresses, every transfer to a particular recipient would publish the recipient's address (or a fixed hash of it) on the chain. Even if the value and sender are hidden, repeated transfers to the same recipient would be observable: "the same recipient received 50 transactions over the past week" is a powerful starting point for deanonymisation, even without knowing who the recipient is.

Stealth addresses solve this by deriving a fresh, unlinkable address for every transfer. A recipient publishes a single long-term *viewing key* and *spending public key*, and senders derive one-time addresses from these such that the recipient can recognise transfers to themselves but no observer can correlate multiple transfers.

### 7.2.2 Construction

The protocol uses a Diffie-Hellman-based stealth address scheme adapted from the Monero and Zcash designs.

A recipient's long-term identity comprises:

- **Spending key** `sk_s`: scalar in the BLS12-381 scalar field
- **Viewing key** `sk_v`: scalar in the BLS12-381 scalar field
- **Spending public key** `pk_s = sk_s · G` where G is the curve generator
- **Viewing public key** `pk_v = sk_v · G`

The recipient's "address" published off-chain (in payment URIs, QR codes, etc.) is `(pk_s, pk_v)`.

To send a note to this recipient, a sender:

1. Generates a fresh random scalar `r`
2. Computes the stealth public key: `R = r · G` (this becomes part of the note's on-chain data)
3. Computes the shared secret: `s = HashToScalar(r · pk_v || domain_tag)`
4. Computes the one-time stealth address: `P = pk_s + s · G`
5. Constructs the note with `recipient = P`

The shared secret `s` derivation uses `pk_v` (the viewing key) so that the recipient can compute `s` using `sk_v` (since `r · pk_v = r · sk_v · G = sk_v · R`).

The recipient's wallet, upon scanning the chain, computes for each note:

1. `s' = HashToScalar(sk_v · R || domain_tag)`
2. `P' = pk_s + s' · G`
3. If `P' == note.recipient`, the note is for this recipient

If the note is theirs, the recipient derives the corresponding spending key as `sk' = sk_s + s'` and uses it to construct the nullifier when spending.

### 7.2.3 Properties

- **Unlinkability.** Two stealth addresses for the same recipient look entirely uncorrelated to anyone without the viewing key. Computing the link requires either `sk_v` or solving the discrete logarithm problem on BLS12-381.
- **No interaction.** The sender does not communicate with the recipient; the stealth address is derived purely from public information.
- **Selective disclosure compatible.** Disclosing the viewing key reveals all notes for the recipient but does not reveal the spending key, so view-key holders can audit but not spend.

### 7.2.4 View tag optimisation

A naive scan of the chain requires the recipient to compute `s'` and `P'` for every note ever created — an operation that becomes prohibitive as the chain grows. The protocol addresses this with a **view tag**: an 8-bit value attached to each note, computed from the shared secret. A wallet scanning notes can quickly reject notes whose view tag does not match the expected value, computing the full check only for the ~1/256 notes that pass the tag filter.

This optimisation is borrowed from Monero's view tag design (introduced 2022). It reduces wallet scan cost by roughly 256× at the cost of a minor reduction in privacy: an attacker observing the view tags of a known recipient can identify roughly 1/256 of notes as candidates for that recipient. This is a substantially weaker signal than full address linkage and is widely accepted as a reasonable trade-off.

## 7.3 Shielded execution circuits

A shielded transaction's correctness is attested by a Halo 2 zero-knowledge proof. The proof asserts that the transaction is valid — every input note exists, every nullifier is correctly derived, every output note is well-formed, every value-conservation rule is respected — without revealing the inputs, the values, or the recipients.

### 7.3.1 Anatomy of a shielded transaction

A shielded transaction comprises:

```
ShieldedTransaction {
    nullifiers:        Vec<Nullifier>,        // notes being spent
    output_commitments: Vec<NoteCommitment>,  // notes being created
    encrypted_outputs:  Vec<EncryptedNote>,   // for recipient delivery
    public_inputs:     PublicInputs,          // explicit transaction parameters
    proof:             Halo2Proof,            // attests to validity
    binding_signature: Signature,             // ties the proof to the transaction
}
```

Public inputs include the nullifiers, the output commitments, the GNCT root being spent against, the asset types involved (which may be partially disclosed for compliance), and any explicit fees. Everything else is hidden.

### 7.3.2 The validity circuit

The Halo 2 circuit that proves validity asserts the following statements:

1. **Input note existence.** For each nullifier, there exists a note commitment in the GNCT (proven via a Merkle path) and the nullifier is correctly derived from the note's contents.

2. **Nullifier uniqueness.** Each published nullifier has not previously appeared on the chain. (This check is partly in-circuit, partly enforced by the consensus layer's nullifier set.)

3. **Output note well-formedness.** Each output commitment is correctly computed from valid inputs (a recipient stealth address, a value, an asset type, randomness).

4. **Value conservation.** The sum of input values equals the sum of output values plus the explicit fees, *per asset type*. This is the property that prevents inflation: a shielded transaction cannot create value from nothing or destroy value silently.

5. **Range proofs.** Every value in the transaction lies in `[0, 2^64)`. Without this, an attacker could create notes with negative values that nominally satisfy value conservation while creating value.

6. **Authority.** For each input note, the prover knows the spending key corresponding to the note's recipient. This is the analog of "the spender authorised the spend."

7. **Smart-contract execution.** For shielded executions of `#[shielded]` Adamant Move functions, the circuit additionally proves that the function executed correctly given the shielded inputs and produced the shielded outputs.

The circuit is large — typical proofs cover tens of thousands of constraints. Halo 2's PLONKish arithmetisation is well suited to this scale; proof size is approximately 1–4 KB depending on the complexity of the shielded computation.

### 7.3.3 Proof generation cost

Generating a Halo 2 proof for a typical shielded transaction takes:

- **Simple transfer (1 input, 2 outputs):** approximately 2–5 seconds on consumer laptop hardware (M2-class CPU), 4–10 seconds on a modern smartphone.
- **Complex shielded contract execution:** can range from 10 seconds to several minutes depending on circuit complexity.

These figures derive from published Halo 2 benchmarks and Aztec's measured proving times for analogous operations (Aztec mainnet, November 2025 onwards). They are improving over time as proving systems mature.

### 7.3.4 Proof verification cost

Verifying a Halo 2 proof is fast: approximately 5–10 milliseconds per proof on commodity hardware, regardless of the proof's circuit size. Validators verify proofs as part of consensus; the verification cost is bounded and predictable.

## 7.4 View keys and selective disclosure

Section 4.4 introduced view keys conceptually. This subsection specifies the cryptographic mechanisms.

### 7.4.1 View key hierarchy

A user's master seed deterministically generates a hierarchical key tree:

```
master_seed
   ├── spending_key (sk_s)
   ├── viewing_key (sk_v) ── full account visibility
   │      ├── time_window_view_key   ── visibility into [t1, t2] only
   │      ├── counterparty_view_key  ── visibility into transactions with X only
   │      ├── amount_threshold_view_key ── visibility into amounts > Y only
   │      └── compliance_view_key    ── visibility into transactions matching rules R
   └── nullifier_key (sk_n) ── deterministic from sk_s
```

The viewing key has full visibility. Sub-view-keys are derived deterministically from the viewing key with parameters specifying their scope. The derivation is one-way: a sub-view-key holder cannot derive the parent viewing key.

### 7.4.2 Sub-view-key construction

A sub-view-key for scope `S` is constructed as:

```
sub_view_key_S = (sk_v + Hash(domain || S || sk_v) · G_aux)
```

Where `G_aux` is a fixed auxiliary curve point and `S` is a structured description of the sub-key's scope (e.g. `{"start": t1, "end": t2}` for a time-windowed key).

The sub-view-key allows the holder to compute the shared secret `s'` for notes that fall within scope `S`, but is cryptographically constructed so that notes outside scope `S` produce nonsense decryption results.

The implementation of "in scope" is enforced by the recipient's wallet, not by the chain: the wallet decides which sub-view-keys to derive and to whom. The chain has no view-key-related logic; it does not know which sub-view-keys exist.

### 7.4.3 Provable disclosure

A user can produce cryptographic proofs of specific facts about their transactions without revealing other facts. Examples:

- "I received at least X ADM from address Y between dates D1 and D2." Prover constructs a Halo 2 proof that some subset of their notes meet these criteria, without revealing which specific notes or what other notes they hold.
- "My current shielded balance is at least Z." Useful for proof-of-solvency to a counterparty.
- "I have not received any notes from sanctioned address X." Useful for compliance assertions where the user wants to prove the negative.

The protocol provides circuit primitives for constructing such proofs (`adamant::privacy::prove_assertion(...)` in the standard library, section 6.5). Wallets expose them as user-friendly operations: "generate audit proof for tax filing", "generate solvency proof for counterparty", etc.

### 7.4.4 Compliance considerations

The view-key mechanism provides users with a strong compliance posture: they can prove facts about their financial activity to legitimate authorities (auditors, tax authorities, regulators with demonstrated legal standing) without exposing unrelated transaction history.

This is a significantly *stronger* compliance posture than transparent chains offer. On a transparent chain, a user complying with a regulatory request must expose their entire transaction history forever, to all observers. On Adamant, the user controls precisely what is disclosed and to whom.

The protocol does **not** include any mechanism for compelled disclosure. There is no key escrow, no master decryption key held by any party, no protocol-level mechanism by which a third party can demand a view key. A user who refuses to disclose simply does not disclose; the protocol does not provide override.

This is not a regulatory loophole; it is a deliberate design choice consistent with Principle I and Principle II. The protocol's view is that compliance is an obligation of the user, not a property the protocol enforces. Users in jurisdictions with disclosure requirements can comply; users facing illegitimate demands have the cryptographic option to refuse.

## 7.5 The shielded pool and anonymity set

The "shielded pool" is the collective set of all unspent shielded notes on the chain. The pool's size is the protocol's anonymity set: every shielded spend is, in principle, indistinguishable from spending any note in the pool.

### 7.5.1 Anonymity set growth

The anonymity set grows monotonically over time, in two senses:

1. **More notes.** As transactions create more notes, the pool grows. A spend's anonymity set is the entire pool at the time of spending.
2. **More age.** The age distribution of notes in the pool widens over time, making timing-correlation attacks harder.

There is no equivalent on Adamant of Monero's "ring size" or Zcash's "selected anonymity set". Every spend is anonymised against the full pool, because the Merkle proof of inclusion reveals only that *some* commitment is being spent.

### 7.5.2 Anonymity set hygiene

Several practices preserve the strength of the anonymity set:

- **Default-shielded transactions.** Because Adamant transactions are shielded by default (Principle II), the anonymity set comprises the entire population of users, not the subset who opted into privacy. This is the most important property: the anonymity set is the chain's user base, not its privacy-conscious subset.

- **Decoy transactions are unnecessary.** Some privacy chains generate decoy traffic to obscure timing patterns. Adamant does not, because the volume of organic shielded traffic at the throughput target is sufficient.

- **No pool segmentation.** All shielded transactions, regardless of asset type or amount, draw from the same anonymity set. There is no "small-value pool" vs "large-value pool"; segmentation would weaken privacy by partitioning users.

### 7.5.3 Known limitations

The anonymity set is a powerful but not unconditional defence:

- **Off-chain context.** If a user known to receive a payment from another known user transfers funds shortly afterward, an observer with off-chain knowledge can draw inferences. The chain's privacy does not protect against off-chain correlation.

- **Statistical attacks at edges.** Users who interact only rarely with the chain present a smaller "behavioural" anonymity set to a sophisticated observer with access to broad metadata (network surveillance, exchange records, etc.). The chain's cryptographic privacy is unconditional, but the *practical* privacy of an individual user depends on their broader operational security.

- **Zero-day cryptographic breaks.** The privacy guarantees rest on Halo 2's soundness, the discrete-log assumption on BLS12-381, and the random-oracle assumption on Poseidon. A break in any of these would compromise privacy. The protocol uses well-studied primitives to minimise this risk but cannot eliminate it.

These limitations are documented because they are real. The protocol does not promise privacy that it cannot deliver.

## 7.6 Encrypted memos

Senders frequently need to communicate context to recipients — invoice numbers, references, free-text notes. The protocol supports this via **encrypted memos** attached to notes.

### 7.6.1 Memo construction

A memo is up to 512 bytes of arbitrary data, encrypted to the recipient's stealth address. The memo is included in the note's encrypted output (the data structure that allows the recipient to decrypt the note's contents) and is invisible to all other parties.

Encryption uses ChaCha20-Poly1305 (section 3.5) with the key derived from the stealth shared secret:

```
memo_key = HashToKey(s || domain_tag_memo)
encrypted_memo = ChaCha20Poly1305(memo_key, nonce, memo_plaintext)
```

The recipient decrypts using their derived shared secret.

### 7.6.2 Memo policies

Applications may define structured memo formats: standard fields for invoices, payment references, etc. The protocol does not prescribe a format; common formats may emerge by convention.

Wallets `SHOULD` warn users that memos are visible to the recipient and to anyone the recipient shares their viewing key with. A "private memo" between sender and recipient is genuinely private only if both parties' operational security is intact.

## 7.7 Prover markets

Generating Halo 2 proofs is computationally significant — seconds on a laptop, longer on a phone for complex contracts. Some users will prefer to outsource proof generation to specialised hardware. The protocol supports this through **prover markets**.

### 7.7.1 Mechanism

A user constructing a shielded transaction can:

1. **Prove locally.** Generate the Halo 2 proof on their own device. The proof reveals nothing to anyone; the user pays only standard transaction fees.

2. **Outsource to a prover.** Encrypt the witness data (the inputs the prover needs) to a chosen prover's public key, submit the witness with a fee offer to the prover market, and receive the completed proof. The prover sees the witness contents (so the user must trust the prover with this data); the chain sees only the final proof.

3. **Outsource via a privacy-preserving prover.** Some prover protocols (using secure enclaves, multi-party computation, or trusted hardware) allow proving without revealing the witness to the prover. These are emerging technologies; the protocol supports them where available but does not require them.

### 7.7.2 The trust model

Outsourcing proof generation is a trust trade-off: the user trades computational convenience for the prover's ability to see (and potentially log) their witness data. For low-value transactions where the witness contents are uninteresting, this is fine. For high-value transactions, users `SHOULD` prove locally or use privacy-preserving proving.

The chain does not enforce this trade-off; it is the user's choice. Wallets `SHOULD` surface the choice clearly.

### 7.7.3 Provers as a market

Multiple provers compete in the market. Provers advertise their fee rates, their hardware, and (where applicable) their privacy-preservation properties. Users select provers based on these criteria.

Provers earn fees in ADM. The protocol does not specify the prover protocol in detail beyond ensuring that the on-chain submission mechanism (a transaction containing a prover-generated proof) works identically to a self-generated proof. The market itself is permissionless: anyone can become a prover.

## 7.8 Privacy and the object model

Section 5.7 anticipated this subsection: how does the privacy layer interact with the object model?

### 7.8.1 Shielded vs transparent objects

An object is either **shielded** or **transparent**, declared at creation:

- **Shielded objects.** The `contents` field is encrypted. State transitions are accompanied by Halo 2 proofs attesting to correctness. The object's existence is public; its contents and ownership details are not.

- **Transparent objects.** The `contents` field is in clear text. State transitions are visible to all observers. Ownership is visible. Useful for public-record applications, public bounties, transparent governance, and any case where the application's purpose requires transparency.

This is a per-object choice, not a per-transaction choice. An object created shielded remains shielded for its lifetime; an object created transparent remains transparent for its lifetime. (A shielded object can produce transparent outputs by explicitly burning to a transparent destination, and vice versa, but the object itself does not switch modes.)

### 7.8.2 Mixed transactions

A single transaction may touch both shielded and transparent objects. The transaction's structure reflects this: shielded portions carry Halo 2 proofs; transparent portions are visible. The mix is common: a user spends shielded notes to pay a transparent contract, or a transparent contract emits shielded notes to a recipient.

The Adamant Move compiler handles the proof generation for the shielded portions automatically when functions are annotated `#[shielded]` (section 6.1.2).

### 7.8.3 Privacy of mutability declarations

Object mutability declarations are *always* in clear text, regardless of whether the object is otherwise shielded. This is mandated by Principle V (mutability must be visible to users before interaction). A user inspecting a contract `MUST` be able to determine its mutability without trust in any party.

## 7.9 Threat model and limitations

This subsection documents what the privacy layer protects against and what it does not.

### 7.9.1 Protected against

- **On-chain analysis.** An adversary observing only the chain learns the existence and structural properties of shielded transactions but not their contents, values, or participants beyond what is publicly disclosed.

- **Validator surveillance.** Validators see the same data as any other on-chain observer; their privileged role in consensus does not give them privileged access to shielded data.

- **Network surveillance of shielded transaction contents.** Encryption between user wallets and the network protects shielded transaction data in transit.

- **Compelled decryption.** No party — including the protocol's original implementers, validators acting in concert, or governments — can decrypt shielded data without the user's cooperation.

### 7.9.2 Not protected against

- **Off-chain correlation.** If the user identifies themselves to a third party (an exchange, a vendor, a service provider) and that party correlates on-chain activity to their off-chain identity, the chain's cryptographic privacy is undefeated but the practical anonymity is reduced.

- **Compromised user devices.** A malware-infected wallet leaks the user's keys and renders cryptographic privacy moot.

- **Operational security failures.** A user reusing the same payment addresses, leaking metadata through transaction timing, or interacting predictably with services that expose their identity reduces their practical anonymity.

- **Quantum cryptanalysis (long-term).** The privacy primitives (BLS12-381, Halo 2) are not post-quantum. A future quantum adversary could retroactively break the privacy of historical shielded transactions. This is a known limitation; the protocol's signature scheme is post-quantum (ML-DSA), but the privacy primitives are not yet, because production-ready post-quantum proving systems do not exist as of this draft. Section 11 specifies the migration path.

- **Side-channel attacks on prover hardware.** When proofs are generated on devices vulnerable to side channels (timing attacks, power analysis, electromagnetic leakage), an adversary with physical access could potentially extract witness data. This is a hardware concern, not a protocol concern.

### 7.9.3 Quantum vulnerability of historical privacy

The protocol acknowledges that a future sufficiently large quantum computer could retroactively break BLS12-381-based discrete-log assumptions and retroactively break Halo 2's privacy guarantees. Transactions made today might, in 2050, be retrospectively decryptable.

This is a real and acknowledged limitation. The protocol's responses:

1. **Forward security via key rotation.** A user who rotates their viewing keys regularly limits the scope of historical decryption to the period under each key.

2. **Forward security of nullifiers.** Even if historical privacy is compromised, nullifiers prevent any reanalysis from triggering double-spends or other consensus violations. The chain's integrity is not at risk; only its historical privacy.

3. **Migration to post-quantum proving.** When post-quantum zk proving systems mature into production-ready form (likely some years after the chain's launch), the protocol can be migrated. New shielded transactions would use the new system. Section 11 specifies the migration mechanism.

The honest assessment: a user requiring privacy that survives the next 25–50 years against nation-state-level adversaries with future quantum computers should not rely on Adamant's privacy layer alone. They should also use operational security measures (separate identities, careful counterparty selection, geographically diverse infrastructure) and consider the eventual post-quantum migration.

For the typical use cases — privacy of financial activity against contemporary adversaries, including most regulatory and commercial threat actors — the protocol's privacy is sound and substantial.

## 7.10 Summary

The privacy layer is constructed from peer-reviewed primitives composed in well-understood patterns:

- **Notes and nullifiers** following Zcash Orchard's design, extended for multi-asset support
- **Stealth addresses** following the Diffie-Hellman construction shared with Monero and Zcash, with view-tag optimisation
- **Halo 2 proofs** for shielded execution validity, leveraging Zcash's production implementation
- **View keys and sub-view-keys** for selective disclosure, structured for granular user control
- **Encrypted memos** for sender-to-recipient context
- **Prover markets** for optional outsourcing of proof generation

The contribution is the integration: a system where these primitives compose cleanly with the object model, the smart-contract language, and the consensus mechanism (specified in section 8 next), to deliver a chain that is genuinely private by default and genuinely usable.
