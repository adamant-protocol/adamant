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

## 7.0 Encryption posture

All shielded encryption in this section uses **probabilistic** schemes. Two encryptions of the same plaintext under the same key produce different ciphertexts; ciphertext equality does not imply plaintext equality. This is a protocol-level commitment, not a per-site convention.

The commitment matters because the runtime's shielded-value-equality semantics (§6.2.1.9) compares ciphertext bytes verbatim — `Bytecode::Eq` on two shielded values returns `true` when the ciphertext bytes match, `false` otherwise. The privacy property — *ciphertext equality reveals nothing about plaintext equality* — depends on the encryption being probabilistic. A deterministic shielded-encryption scheme would silently break this property: two equal plaintexts would produce equal ciphertexts, and an observer could detect plaintext equality by ciphertext comparison without holding the key.

The §7.0 posture binds every on-chain shielded-encryption surface in this section. The surfaces and their per-site specification status as of this amendment:

- **Note commitments** (§7.1) — Poseidon hash with per-note `randomness: [u8; 32]`. Scheme fully specified by §7.1; probabilistic by construction (the per-note randomness ensures uncorrelated commitments for byte-equal `(value, asset_type, recipient, metadata)` tuples).
- **Stealth-address ciphertexts** (§7.2.2) — ML-KEM-768 encapsulation per FIPS 203. Scheme fully specified by §7.2.2; probabilistic by FIPS 203 §6.3 (a fresh `m ← {0,1}^256` is sampled per encapsulation call).
- **Encrypted memos** (§7.6.1) — ChaCha20-Poly1305 with `memo_key = HashToKey(s || domain_tag_memo)`. Scheme partially specified by §7.6.1; the nonce-derivation half is not pinned at this amendment and remains open per the §3.5 framing ("Implementation details for nonce derivation are specified per-use in subsequent sections"). The §7.0 posture binds the eventual specification to a probabilistic shape.
- **Encrypted note delivery** (§7.3.1 `encrypted_outputs: Vec<EncryptedNote>`) — encryption scheme not specified at this amendment. The §7.0 posture binds the eventual specification to a probabilistic shape.
- **Shielded object contents** (§7.8.1) — encryption scheme not specified at this amendment. The §7.0 posture binds the eventual specification to a probabilistic shape.

Per-site specifications for the three open surfaces (memo nonce derivation, encrypted-note delivery, shielded object contents) are subsequent §7 substantive work. The §7.0 posture pre-binds them: any scheme that lands at those subsections must be probabilistic. An implementation that proceeds with an as-yet-unspecified surface — for example, by choosing a default scheme for shielded object contents — must choose a probabilistic scheme to be conformant.

**Surfaces the posture does not bind.** Out-of-protocol encryption — for example, witness encryption between a user and a prover in the prover market (§7.7.1) — is operationally distinct from on-chain shielded encryption. The §6.2.1.9 shielded-value-equality runtime semantics applies only to on-chain ciphertext bytes; out-of-protocol encryption is the user's choice and does not affect consensus.

**Anti-pattern (explicitly forbidden).** Deterministic encryption schemes — for example, AES-ECB, AES-SIV with deterministic IV, or Poseidon-as-encryption without per-input randomness — are not admitted for any on-chain shielded-encryption surface. An implementation that substitutes a deterministic scheme is non-conforming, regardless of whether the scheme is otherwise cryptographically strong: the conformance break is at the privacy-property level, not the cryptographic-strength level.

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

The protocol uses an **ML-KEM-based stealth address scheme**, providing post-quantum-secure key agreement (Principle VIII, section 2.8). Earlier drafts of this whitepaper specified a Diffie-Hellman scheme on BLS12-381 (analogous to Zcash Sapling/Orchard); that scheme is replaced here because Diffie-Hellman key agreement on BLS12-381 is not post-quantum-secure, and historical privacy is a permanent property that must survive future quantum cryptanalysis.

A recipient's long-term identity comprises:

- **Spending key** `sk_s`: scalar in the **Pallas scalar field** (used for nullifier derivation and spending-address authorization; see section 7.2.5 for hybrid-mode signature considerations, which are independent of the stealth-address arithmetic)
- **Viewing keypair** `(sk_v_kem, pk_v_kem)`: an ML-KEM-768 keypair (public key 1184 bytes, secret key 2400 bytes)
- **Spending public key** `pk_s = sk_s · G` where G is the **Pallas curve generator**

The recipient's "address" published off-chain (in payment URIs, QR codes, etc.) is `(pk_s, pk_v_kem)`. `pk_s` is a Pallas point encoded as its 32-byte canonical compressed form (x-coordinate plus sign bit). ML-KEM public keys are larger than ECDH public keys, so the combined address is dominated by `pk_v_kem` (1184 bytes); address-encoding formats accommodate this (Bech32m at appropriate length, QR codes scaled correspondingly).

To send a note to this recipient, a sender:

1. Performs ML-KEM-768 encapsulation against `pk_v_kem`, producing `(ct, ss)` where `ct` is a 1088-byte ciphertext and `ss` is a 32-byte shared secret
2. Stores `ct` as part of the note's on-chain data (analogous to the `R` element in classical schemes)
3. Computes the shared scalar: `s = HashToScalar(ss || domain_tag)` where `HashToScalar` produces a **Pallas scalar field element**
4. Computes the one-time stealth address: `P = pk_s + s · G` (a Pallas point)
5. Constructs the note with `recipient = P`, where `recipient` is the canonical 32-byte encoding of `P`'s base-field x-coordinate (the same Pallas-base-field element width as the rest of the note-commitment inputs per section 7.1)

The recipient's wallet, upon scanning the chain, performs for each note:

1. ML-KEM-768 decapsulation: `ss' = Decap(sk_v_kem, ct)`
2. `s' = HashToScalar(ss' || domain_tag)`
3. `P' = pk_s + s' · G`
4. If `P' == note.recipient`, the note is for this recipient

If the note is theirs, the recipient derives the corresponding spending key as `sk' = sk_s + s'` and uses it to construct the nullifier when spending.

**Why ML-KEM and not curve ECDH.** ECDH on any elliptic curve over a finite field is broken by Shor's algorithm; a future quantum adversary observing historical chain state can recover `r · pk_v` from `(r · G, pk_v)` by computing the discrete logarithm. ML-KEM is lattice-based and presumed post-quantum-secure; encapsulation outputs cannot be retroactively broken by quantum attack. The cost of this protection is the per-note ciphertext size (1088 bytes vs ~32 bytes for ECDH); this is amortised across the note's lifetime and is acceptable given the permanence of the privacy guarantee.

**Cross-curve note.** The stealth-address arithmetic above operates on the **Pasta cycle** (Pallas/Vesta), matching Halo 2's native field per section 3.9.1 and Poseidon's field of definition per section 3.3.3. This is intentional: stealth addresses appear as the `recipient` field inside note commitments (section 7.1), which are hashed in-circuit by Poseidon; placing the address arithmetic on Pallas keeps the in-circuit verification native and avoids non-native arithmetic emulation. The protocol's *other* curve, BLS12-381, is used independently for KZG vector commitments (section 3.9.2), threshold encryption (section 3.6), and validator BLS signatures (section 3.4.3); BLS12-381 does not appear in stealth-address derivation. Pre-amendment drafts of section 7.2.2 specified BLS12-381 for the stealth-address arithmetic; that conflicted with section 3.3.3's amended Poseidon field-of-definition (Pallas) and section 7.1's commitment formula. The amendment unifies the privacy-layer arithmetic on Pasta cycle native fields, parallel to the section 3.3.3 amendment instance 31.

**Bytecode-level construction.** Section 6.2.1.4's `MlKemEncapsulate` and `MlKemDecapsulate` instructions perform the ML-KEM operations inside Adamant Move shielded circuits. The compiler emits these instructions automatically when `#[shielded]` functions construct or process notes; contract authors do not invoke them directly.

### 7.2.3 Properties

- **Unlinkability.** Two stealth addresses for the same recipient look entirely uncorrelated to anyone without the viewing keypair. Computing the link requires either `sk_v_kem` or breaking ML-KEM, which is presumed hard against both classical and quantum adversaries.
- **No interaction.** The sender does not communicate with the recipient; the stealth address is derived purely from public information.
- **Selective disclosure compatible.** Disclosing the viewing keypair reveals all notes for the recipient but does not reveal the spending key, so view-key holders can audit but not spend.
- **Post-quantum secure.** Future quantum cryptanalysis cannot retroactively deanonymise transactions that used ML-KEM-derived stealth addresses. This is the substantive improvement over the classical scheme this construction replaces.

### 7.2.4 View tag optimisation

A naive scan of the chain requires the recipient to compute `s'` and `P'` for every note ever created — an operation that becomes prohibitive as the chain grows. The protocol addresses this with a **view tag**: an 8-bit value attached to each note, computed from the shared secret. A wallet scanning notes can quickly reject notes whose view tag does not match the expected value, computing the full check only for the ~1/256 notes that pass the tag filter.

The view tag is computed as `view_tag = SHA3_256(ss || tag_domain)[0]` where `ss` is the ML-KEM shared secret. Wallets first compute the view tag from the candidate decapsulation, compare it to the on-chain tag, and proceed to the full address derivation only on match.

This optimisation is borrowed from Monero's view tag design (introduced 2022), adapted to the ML-KEM construction. It reduces wallet scan cost by roughly 256× at the cost of a minor reduction in privacy: an attacker observing the view tags of a known recipient can identify roughly 1/256 of notes as candidates for that recipient. This is a substantially weaker signal than full address linkage and is widely accepted as a reasonable trade-off.

### 7.2.5 Spending key in hybrid signature mode

The spending key `sk_s` controls authorisation to spend notes received at stealth addresses. Per Principle VIII (hybrid signatures), users may configure spending authorization via either Ed25519 (default for routine spending) or ML-DSA (opt-in for elevated threat models). The wallet derives both from the same master seed via HKDF-SHA3 with distinct domain separators.

The protocol's nullifier derivation (section 7.1.2) is independent of the spending signature scheme: nullifiers commit to the note position and the spending key, not to the signature. A user who later opts up from Ed25519 to ML-DSA spending does not invalidate previously-derived nullifiers; the spending key material is the same, only the signature scheme over the spend transaction changes.

## 7.3 Shielded execution circuits

A shielded transaction's correctness is attested by a Halo 2 zero-knowledge proof. The proof asserts that the transaction is valid — every input note exists, every nullifier is correctly derived, every output note is well-formed, every value-conservation rule is respected — without revealing the inputs, the values, or the recipients.

### 7.3.1 Anatomy of a shielded transaction

A shielded transaction comprises:

```
ShieldedTransaction {
    nullifiers:               Vec<Nullifier>,         // notes being spent
    input_value_commitments:  Vec<ValueCommitment>,   // hiding commitments for input values (one per nullifier, same order)
    output_commitments:       Vec<NoteCommitment>,    // notes being created
    output_value_commitments: Vec<ValueCommitment>,   // hiding commitments for output values (one per output_commitment, same order)
    encrypted_outputs:        Vec<EncryptedNote>,     // for recipient delivery
    public_inputs:            PublicInputs,           // explicit transaction parameters
    proof:                    Halo2Proof,             // attests to validity
    binding_signature:        Signature,              // ties the proof to the transaction
}
```

Public inputs include the nullifiers, the output commitments, the input and output value commitments, the GNCT root being spent against, the asset types involved (which may be partially disclosed for compliance), and any explicit fees. Everything else is hidden.

The `input_value_commitments` array is parallel to `nullifiers` (index `i` of one corresponds to index `i` of the other); the `output_value_commitments` array is parallel to `output_commitments`. The two sequences let validators perform the homomorphic balance check at consensus time without learning the underlying values; see §7.3.1.2 for the construction and §7.3.2 statement 4 for the balance constraint.

#### 7.3.1.1 EncryptedNote construction

An `EncryptedNote` is the on-chain ciphertext that allows the recipient to decrypt the note's contents upon scanning the chain. The construction:

```
EncryptedNote {
    ml_kem_ciphertext: [u8; 1088],  // ML-KEM encapsulation
    chacha_ciphertext: Vec<u8>,     // encrypted note payload
    auth_tag:          [u8; 16],    // Poly1305 authentication tag
}
```

A sender constructs an `EncryptedNote` as:

1. ML-KEM-768 encapsulation against recipient's `pk_v_kem` per §7.2.2: `(ml_kem_ciphertext, ss) = ML-KEM-768.Encap(pk_v_kem)`
2. Derive symmetric key: `note_key = HKDF-SHA3(salt = domain_tag_note_key, ikm = ss, info = note_position_bytes, L = 32)` where `domain_tag_note_key = b"ADAMANT-v1-note-key"` and `note_position_bytes` is the 8-byte little-endian note position in the global note commitment tree
3. Derive nonce: `note_nonce = SHA3_256(ss || domain_tag_note_nonce)[0..12]` where `domain_tag_note_nonce = b"ADAMANT-v1-note-nonce"`
4. Encrypt note payload (BCS-encoded note tuple per §7.1): `(chacha_ciphertext, auth_tag) = ChaCha20Poly1305-Encrypt(note_key, note_nonce, note_payload)`

The recipient decrypts by ML-KEM decapsulation against `sk_v_kem`, derives the same `note_key` + `note_nonce` from the recovered shared secret, and applies `ChaCha20Poly1305-Decrypt`.

**Probabilistic property satisfied per §7.0.** Per-note ML-KEM encapsulation produces a fresh `ss` per FIPS 203 §6.3 (randomized encapsulation); the derived `note_key` + `note_nonce` are per-note unique; ciphertexts are uncorrelated across notes even for byte-equal note payloads.

#### 7.3.1.2 Value commitments

A `ValueCommitment` is a 32-byte Pedersen-style commitment on the Pallas curve that hides a note's value while remaining additively homomorphic, so the chain can verify per-asset-type value conservation (§7.3.2 statement 4) without learning any individual value.

**Construction.** For a note with value `v: u64`, asset type `τ: TypeId`, and per-commitment randomness `r ∈ Pallas scalar field`:

```
vc = v · V_τ + r · R   (a Pallas point)
```

where:

- `V_τ` is the asset-specific value generator: `V_τ = HashToCurve("ADAMANT-v1-vc-base", τ_bytes)` — a Pallas point derived deterministically from the 32-byte canonical encoding of the asset type via the `pasta_curves` `Point::hash_to_curve` construction (Simplified SWU map per IRTF `draft-irtf-cfrg-hash-to-curve`).
- `R` is the universal randomness generator: a single fixed Pallas point derived once via `R = HashToCurve("ADAMANT-v1-vc-randomness", b"")`. `R` is independent of every `V_τ` (different domain tag); the discrete log of `R` with respect to any `V_τ` is unknown to all parties (genuinely random Pallas point).
- The on-chain encoding of `vc` is the 32-byte canonical compressed Pallas point form (x-coordinate plus 1-bit y-sign per pasta_curves' `GroupEncoding`), matching the `recipient` stealth-address encoding in §7.2.2.

**Properties.**

- **Hiding.** The `r · R` term blinds the value; without knowing `r`, an observer cannot recover `v` (computational hiding under the discrete-log assumption on Pallas).
- **Asset-type hiding.** The randomness blinding extends to the asset-specific component: an observer cannot determine `τ` from `vc` alone (cannot distinguish `(v_1, τ_1, r_1)` from `(v_2, τ_2, r_2)` without solving multi-discrete-log).
- **Binding.** Given `vc`, the opening `(v, τ, r)` is computationally unique under the discrete-log assumption (a different opening would reveal a discrete-log relation between `V_τ` and `R`).
- **Additively homomorphic.** `vc(v_1, τ, r_1) + vc(v_2, τ, r_2) = vc(v_1 + v_2, τ, r_1 + r_2)` (point addition on Pallas, per-asset-type group). Cross-asset addition does NOT preserve commitment shape (the `V_{τ_1}` and `V_{τ_2}` generators are independent), which is exactly what makes the per-asset-type balance check work.

**Per-input vs per-output randomness.** Each input note's `vc_in` carries a randomness `r_in_i` known to the spender; each output note's `vc_out` carries a randomness `r_out_j` known to the sender. The §7.3.2 statement 4 balance equation requires the randomness sums to cancel: `Σ r_in - Σ r_out = r_balance`, where `r_balance` is committed to by the [`binding_signature`] (§7.3.1) — the binding signature is over a transcript that includes `Σ vc_in - Σ vc_out` and is signed under the key `r_balance · R`. This is the standard Sapling-style binding-signature pattern (Hopwood / Bowe / Hornby / Wilcox 2020); a successful binding signature attests both that the spender chose a randomness assignment such that the per-asset-type values balance AND that the full transaction (proof + commitments) is bound to a single coherent randomness sum.

**Construction of `R` and `V_τ`.** Genesis-fixed; the byte tags `b"ADAMANT-v1-vc-base"` and `b"ADAMANT-v1-vc-randomness"` are part of the consensus rules per §3.3.1 (changing them is a hard fork). Wallet implementations MUST derive `R` lazily once at startup and cache it; `V_τ` is derived per asset type the wallet handles.

### 7.3.2 The validity circuit

The Halo 2 circuit that proves validity asserts the following statements:

1. **Input note existence.** For each nullifier, there exists a note commitment in the GNCT (proven via a Merkle path) and the nullifier is correctly derived from the note's contents.

2. **Nullifier uniqueness.** Each published nullifier has not previously appeared on the chain. (This check is partly in-circuit, partly enforced by the consensus layer's nullifier set.)

3. **Output note well-formedness.** Each output commitment is correctly computed from valid inputs (a recipient stealth address, a value, an asset type, randomness).

4. **Value conservation.** The sum of input values equals the sum of output values plus the explicit fees, *per asset type*. This is the property that prevents inflation: a shielded transaction cannot create value from nothing or destroy value silently.

   Enforced via the homomorphic value commitments of §7.3.1.2. The validity circuit attests that each per-input and per-output value commitment is correctly constructed (the prover knows `(v, τ, r)` openings consistent with the corresponding note commitment). The chain-level balance check is then a single point equation evaluated on public data:

   ```
   Σ vc_in − Σ vc_out − Σ_τ (fee_τ · V_τ) = r_balance · R
   ```

   Validators verify this equation and the binding signature over the same transcript (§7.3.1.2). Both checks are public-data-only — no zero-knowledge proof is needed for the balance equation itself; the proof is needed only for the per-commitment opening attestation. The balance check is per-asset-type implicitly: because `V_τ` is independent across asset types (§7.3.1.2 hash-to-curve construction), the balance equation can hold only if for every τ in the transaction, `Σ_in v_τ = Σ_out v_τ + fee_τ` (otherwise the `V_τ` term would not cancel).

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

A sub-view-key for scope `S` is a deterministically derived ML-KEM-768 keypair:

```
sub_seed_S = HKDF-SHA3(
    salt = domain_tag_subview,
    ikm  = sk_v_kem_seed,
    info = BCS(S),
    L    = 64
)
(sub_sk_v_kem_S, sub_pk_v_kem_S) = ML-KEM-768.KeyGen(sub_seed_S)
```

where:

- `sk_v_kem_seed` is the 64-byte canonical seed of the parent viewing keypair `(sk_v_kem, pk_v_kem)` per §7.2.2
- `domain_tag_subview = b"ADAMANT-v1-subview-derive"`
- `S` is the structured scope descriptor (e.g. `{"start": t1, "end": t2}` for a time-windowed key); `BCS(S)` is its canonical encoding per §5.1.8
- HKDF-SHA3 is the HKDF construction per RFC 5869 instantiated with SHA3-256, matching the HKDF usage for spending-key derivation per §7.2.5
- L = 64 produces the 64-byte seed required for ML-KEM-768 deterministic key generation per FIPS 203 §6.1
- ML-KEM-768.KeyGen is the FIPS 203 deterministic key-generation function

Properties:

- **One-way derivation.** A sub-view-key holder cannot derive the parent viewing-keypair seed. HKDF-SHA3 is cryptographically one-way; reversing the derivation requires breaking SHA3-256 preimage resistance.
- **Scope-bound decapsulation.** The sub-view-key holder can decapsulate notes whose stealth-address derivation used the same ML-KEM public key family (i.e., notes within scope `S`). Notes outside scope `S` were encapsulated against the parent `pk_v_kem`, not `sub_pk_v_kem_S`; decapsulating them with the sub-view-key produces deterministic-but-meaningless results per FIPS 203 §6.4.1 implicit rejection.
- **Determinism.** Same parent seed + same scope `S` always produces the same sub-view-key. No per-derivation entropy.

The implementation of "in scope" — which sub-view-keys to derive and to whom — is enforced by the recipient's wallet, not by the chain. The chain has no sub-view-key awareness.

**Bytecode-level construction.** Section 6.2.1.4's `ReleaseSubViewKey` instruction performs the HKDF-SHA3 derivation step; ML-KEM-768.KeyGen from the derived seed is performed by the wallet outside shielded execution (the runtime does not need to materialise the keypair; only the seed is exposed via `ReleaseSubViewKey`).

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

The nonce is derived deterministically from the per-note shared secret to ensure non-reuse:

```
nonce = SHA3_256(s || domain_tag_memo_nonce)[0..12]
```

where `s` is the per-note ML-KEM shared secret per §7.2.2 and `domain_tag_memo_nonce = b"ADAMANT-v1-memo-nonce"`. The 12-byte truncation matches ChaCha20-Poly1305's 96-bit nonce width per §3.5.

Nonce non-reuse follows from `s` being per-note (each note has fresh ML-KEM encapsulation per §7.2.2) and the domain tag preventing cross-protocol nonce collision. The construction satisfies the §7.0 encryption-posture probabilistic-only requirement: equal memo plaintexts under different notes encrypt under different `(memo_key, nonce)` pairs and produce uncorrelated ciphertexts.

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

- **Shielded objects.** The `contents` field is encrypted using the following construction:

```
shielded_contents {
    object_key_ciphertext: [u8; 1088],  // ML-KEM encapsulation
    contents_ciphertext:   Vec<u8>,     // encrypted contents
    auth_tag:              [u8; 16],    // Poly1305 tag
    update_nonce:          [u8; 12],    // per-update nonce
}
```

The `object_key_ciphertext` is an ML-KEM-768 encapsulation against the owner's viewing public key `pk_v_kem` per §7.2.2, performed at object creation or owner-rotation. The encapsulated shared secret `ss_obj` is the long-term object-level key material. Per-update encryption derives the symmetric key as `update_key = HKDF-SHA3(salt = domain_tag_object_update, ikm = ss_obj, info = object_id || version_u64_le, L = 32)` where `domain_tag_object_update = b"ADAMANT-v1-object-update"`. The `update_nonce` is sampled fresh per write (random 12-byte value); encryption is `(contents_ciphertext, auth_tag) = ChaCha20Poly1305-Encrypt(update_key, update_nonce, contents_payload)`.

State transitions update `contents_ciphertext` + `update_nonce` together; `object_key_ciphertext` rotates only on owner change. State transitions are accompanied by Halo 2 proofs attesting to correctness. The object's existence is public; its contents and ownership details are not.

The construction satisfies the §7.0 encryption-posture probabilistic-only requirement: per-update random nonce ensures equal `contents_payload` across updates produces uncorrelated ciphertexts.

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

- **Quantum cryptanalysis (long-term).** The Halo 2 proving system is not post-quantum: it relies on discrete-log assumptions that Shor's algorithm breaks. A future quantum adversary could retroactively break the soundness of historical Halo 2 proofs, which means a quantum adversary could in principle produce false witnesses for historical state transitions — but they cannot retroactively *change* committed history because the commitments themselves are SHA-3-based and post-quantum-secure. The implications and limits are addressed in subsection 7.9.3.

  Stealth address derivation and encrypted memo delivery use ML-KEM-768 (section 3.7) and are post-quantum-secure. This is a substantive change from earlier drafts of this whitepaper, which specified BLS12-381 ECDH for these surfaces; that scheme would not have survived quantum cryptanalysis. With the ML-KEM construction, historical privacy of shielded transactions is preserved against future quantum adversaries.

  The chain's signature layer is hybrid post-quantum (Principle VIII): identity layer (addresses, validator registrations, contract deployments) is post-quantum-secure via ML-DSA; ordinary transaction signatures use Ed25519 by default with ML-DSA available per-transaction.

- **Side-channel attacks on prover hardware.** When proofs are generated on devices vulnerable to side channels (timing attacks, power analysis, electromagnetic leakage), an adversary with physical access could potentially extract witness data. This is a hardware concern, not a protocol concern.

### 7.9.3 Quantum vulnerability of historical proof soundness

The protocol acknowledges that a future sufficiently large quantum computer could retroactively break Halo 2's discrete-log-based soundness assumptions. A quantum adversary could in principle produce a Halo 2 proof that verifies for a false statement, which would compromise the soundness of historical shielded-transaction proofs.

Importantly, this is a different concern from the quantum vulnerability addressed by ML-KEM (section 3.7). Two surfaces should be distinguished:

1. **Key agreement** (stealth addresses, encrypted memos) is post-quantum-secure via ML-KEM. Historical privacy — who sent what to whom — survives the quantum threshold because the encapsulation cannot be retroactively broken.

2. **Proof soundness** (Halo 2 attestations of correct state transition) is not post-quantum. A quantum adversary could in principle produce false proofs for historical transactions; combined with control of a sufficient validator set, this could be used to retroactively claim that invalid state transitions had been validly proven.

The chain's responses to the proof-soundness concern:

1. **Forward-only impact.** Quantum forgery of historical proofs requires also rewriting the chain's recursive proof history forward from the point of forgery. The recursive proof's commitments (via SHA-3 and KZG) are post-quantum-binding; an adversary cannot insert a forged proof into committed history without breaking the cryptographic anchors that bind history to the genesis state.

2. **Forward security of nullifiers.** Even if historical proof soundness is compromised, nullifiers prevent any reanalysis from triggering double-spends or other consensus violations on the running chain. The chain's integrity going forward is not at risk; only retrospective claims about historical statement validity.

3. **Migration to post-quantum proving.** When post-quantum zk proving systems mature into production-ready form (likely some years after the chain's launch), the protocol can be migrated. New shielded transactions would use the new system. Section 11 specifies the migration mechanism.

The honest assessment: a user requiring privacy *and* dispute-resolution-grade proof soundness that survives the next 25–50 years against nation-state-level adversaries with future quantum computers should not rely on Adamant's privacy layer alone. They should also use operational security measures (separate identities, careful counterparty selection, geographically diverse infrastructure) and consider the eventual post-quantum migration.

For the typical use cases — privacy of financial activity against contemporary adversaries, including most regulatory and commercial threat actors — the protocol's privacy is sound and substantial. Historical privacy (who-sent-to-whom) is post-quantum-secure via ML-KEM; only proof-soundness retrospective attack remains as a limitation, and even that is bounded by the post-quantum-binding commitments that anchor chain history.

## 7.10 Summary

The privacy layer is constructed from peer-reviewed primitives composed in well-understood patterns:

- **Notes and nullifiers** following Zcash Orchard's design, extended for multi-asset support
- **Stealth addresses** using ML-KEM-768 (FIPS 203) post-quantum key encapsulation, replacing the classical BLS12-381 ECDH that earlier drafts of this whitepaper specified — historical privacy is now post-quantum-secure
- **Halo 2 proofs** for shielded execution validity, leveraging Zcash's production implementation
- **View keys and sub-view-keys** for selective disclosure, structured for granular user control
- **Encrypted memos** using ML-KEM-768 for sender-to-recipient context, post-quantum-secure
- **Prover markets** for optional outsourcing of proof generation

The contribution is the integration: a system where these primitives compose cleanly with the object model, the smart-contract language, and the consensus mechanism (specified in section 8 next), to deliver a chain that is genuinely private by default, post-quantum-secure at the privacy-relevant key-agreement surfaces, and genuinely usable.