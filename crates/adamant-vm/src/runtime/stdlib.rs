//! Adamant standard-library native handlers — whitepaper §6.5.
//!
//! Phase 5/6.8 ships per-stdlib-module native handlers that the
//! AVM dispatch loop routes to via the
//! [`crate::runtime::NativeRegistry`] (Phase 5/6.7.C foundation,
//! Phase 5/6.8.A dispatch hook).
//!
//! Per whitepaper §6.5 amendment, the runtime-dispatched stdlib
//! modules are: `adamant::module`, `adamant::tx_context`,
//! `adamant::object`, `adamant::hash`, `adamant::signature`,
//! `adamant::privacy`, and `adamant::address`. The remainder
//! (`adamant::primitives`, `adamant::token`, `adamant::nft`,
//! `adamant::governance`, `adamant::recovery`) are application-
//! level Move modules. Phase 5/6.8 ships handlers for the
//! pure-function subset (hash + signature + address); the chain-
//! state-mutating handlers (`adamant::module::deploy`,
//! `adamant::object::transfer/freeze/share`,
//! `adamant::tx_context::sender`) require additional
//! [`crate::runtime::NativeContext`] extensions and ship in
//! follow-up sub-arcs.
//!
//! # Genesis registry
//!
//! [`genesis_native_registry`] returns a fully-populated
//! [`NativeRegistry`] with every stdlib native handler registered
//! under its canonical (`STDLIB_ADDRESS`, module-name,
//! function-name) [`NativeKey`]. Per the §6.5 amendment, the
//! mapping is genesis-fixed: adding or removing a handler is a
//! hard fork. Callers construct the registry once at runtime
//! initialisation and pass `Some(&registry)` to
//! [`crate::runtime::interpreter::run`] for every transaction.
//!
//! # Argument decoding
//!
//! Stdlib handlers consume `vector<u8>` arguments as
//! [`crate::runtime::runtime_value::Container::Vector`] of
//! [`RuntimeValue::U8`] entries (matching Move's `vector<u8>`
//! representation). The [`pop_byte_vector`] helper extracts the
//! raw bytes for cryptographic operations. Return values flow
//! the same way: byte arrays are wrapped into a
//! [`Container::Vector`] of `RuntimeValue::U8` entries.

use std::cell::RefCell;
use std::rc::Rc;

use adamant_bytecode_format::Identifier;
use adamant_crypto::hash;
use adamant_crypto::sig_classical;
use adamant_crypto::sig_pq;
use adamant_types::Address;

use crate::runtime::error::{InvariantViolationReason, VMError};
use crate::runtime::native::{NativeContext, NativeKey, NativeRegistry, STDLIB_ADDRESS};
use crate::runtime::runtime_value::{Container, RuntimeValue};

// ---------------------------------------------------------------
// Argument / return helpers
// ---------------------------------------------------------------

/// Extract the next argument from `ctx.args`. Returns
/// [`InvariantViolationReason::StackUnderflow`] if the args
/// vector is empty (residual binding for verifier signature
/// arity-check).
fn pop_arg(ctx: &mut NativeContext<'_>) -> Result<RuntimeValue, VMError> {
    ctx.args.pop().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::StackUnderflow,
    })
}

/// Convert a [`RuntimeValue::Container(Container::Vector)`] of
/// [`RuntimeValue::U8`] entries into a raw `Vec<u8>`. Returns
/// [`InvariantViolationReason::TypeMismatch`] for any other
/// shape.
fn into_byte_vec(value: RuntimeValue) -> Result<Vec<u8>, VMError> {
    let RuntimeValue::Container(Container::Vector(rc)) = value else {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        });
    };
    let elements = rc.borrow();
    let mut out = Vec::with_capacity(elements.len());
    for el in elements.iter() {
        let RuntimeValue::U8(b) = el else {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            });
        };
        out.push(*b);
    }
    Ok(out)
}

/// Wrap a raw `&[u8]` slice into a
/// [`RuntimeValue::Container(Container::Vector)`] of
/// [`RuntimeValue::U8`] entries — Move's `vector<u8>`
/// representation.
fn byte_slice_to_runtime_value(bytes: &[u8]) -> RuntimeValue {
    let elements: Vec<RuntimeValue> = bytes.iter().copied().map(RuntimeValue::U8).collect();
    RuntimeValue::Container(Container::Vector(Rc::new(RefCell::new(elements))))
}

/// Pop a `vector<u8>` argument as raw bytes. Convenience helper
/// composing [`pop_arg`] + [`into_byte_vec`].
fn pop_byte_vector(ctx: &mut NativeContext<'_>) -> Result<Vec<u8>, VMError> {
    into_byte_vec(pop_arg(ctx)?)
}

/// Pop an [`Address`] argument. Move address args reach the
/// runtime as [`RuntimeValue::Address`].
fn pop_address(ctx: &mut NativeContext<'_>) -> Result<Address, VMError> {
    match pop_arg(ctx)? {
        RuntimeValue::Address(a) => Ok(a),
        _ => Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        }),
    }
}

// ---------------------------------------------------------------
// adamant::hash native handlers
// ---------------------------------------------------------------

/// `adamant::hash::sha3_256(input: vector<u8>): vector<u8>`
///
/// SHA3-256 hash of the input bytes per whitepaper §3.3 (the
/// protocol's primary cryptographic hash). Returns a 32-byte
/// `vector<u8>`.
fn hash_sha3_256(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let input = pop_byte_vector(ctx)?;
    let digest = hash::sha3_256_plain(&input);
    ctx.return_values.push(byte_slice_to_runtime_value(&digest));
    Ok(())
}

/// `adamant::hash::blake3(input: vector<u8>): vector<u8>`
///
/// BLAKE3 hash of the input bytes per whitepaper §3.3.2. Returns
/// a 32-byte `vector<u8>`.
fn hash_blake3(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let input = pop_byte_vector(ctx)?;
    let digest = hash::blake3(&input);
    ctx.return_values.push(byte_slice_to_runtime_value(&digest));
    Ok(())
}

// ---------------------------------------------------------------
// adamant::signature native handlers
// ---------------------------------------------------------------

/// `adamant::signature::verify_ed25519(signature: vector<u8>,
///   message: vector<u8>, public_key: vector<u8>): bool`
///
/// Ed25519 signature verification per whitepaper §3.4.1. Returns
/// `true` iff the signature is valid for the message under the
/// given public key. Malformed signature/key bytes (wrong length,
/// invalid encoding) cause `false` to be returned, not an error —
/// signature verification is a boolean check, not an error path.
///
/// Argument order on the Move stack: the function is declared
/// with parameters `(signature, message, public_key)`; arguments
/// land in `ctx.args` in declaration order (`args[0] == signature`,
/// etc.). Pop happens in reverse via [`pop_arg`] (LIFO).
fn signature_verify_ed25519(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    // Reverse-order pop: public_key, message, signature.
    let public_key_bytes = pop_byte_vector(ctx)?;
    let message = pop_byte_vector(ctx)?;
    let signature_bytes = pop_byte_vector(ctx)?;
    let valid = verify_ed25519_inner(&signature_bytes, &message, &public_key_bytes);
    ctx.return_values.push(RuntimeValue::Bool(valid));
    Ok(())
}

fn verify_ed25519_inner(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    // Ed25519 signature: 64 bytes; verifying key: 32 bytes (whitepaper §3.4.1).
    let Ok(sig_arr): Result<[u8; 64], _> = signature.try_into() else {
        return false;
    };
    let Ok(pk_arr): Result<[u8; 32], _> = public_key.try_into() else {
        return false;
    };
    let Ok(verifying_key) = sig_classical::VerifyingKey::from_bytes(&pk_arr) else {
        return false;
    };
    let signature = sig_classical::Signature::from_bytes(&sig_arr);
    verifying_key.verify(message, &signature).is_ok()
}

/// `adamant::signature::verify_ml_dsa_65(signature: vector<u8>,
///   message: vector<u8>, public_key: vector<u8>): bool`
///
/// ML-DSA-65 (CRYSTALS-Dilithium FIPS 204) signature verification
/// per whitepaper §3.4.2. Returns `true` iff the signature is
/// valid for the message under the given public key. Malformed
/// signature/key bytes cause `false` to be returned.
fn signature_verify_ml_dsa_65(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let public_key_bytes = pop_byte_vector(ctx)?;
    let message = pop_byte_vector(ctx)?;
    let signature_bytes = pop_byte_vector(ctx)?;
    let valid = verify_ml_dsa_65_inner(&signature_bytes, &message, &public_key_bytes);
    ctx.return_values.push(RuntimeValue::Bool(valid));
    Ok(())
}

fn verify_ml_dsa_65_inner(signature: &[u8], message: &[u8], public_key: &[u8]) -> bool {
    let Ok(sig_arr): Result<[u8; sig_pq::SIGNATURE_BYTES], _> = signature.try_into() else {
        return false;
    };
    let Ok(pk_arr): Result<[u8; sig_pq::PUBLIC_KEY_BYTES], _> = public_key.try_into() else {
        return false;
    };
    let verifying_key = sig_pq::VerifyingKey::from_bytes(&pk_arr);
    let Ok(signature) = sig_pq::Signature::from_bytes(&sig_arr) else {
        return false;
    };
    verifying_key.verify(message, &signature).is_ok()
}

// ---------------------------------------------------------------
// adamant::address native handlers
// ---------------------------------------------------------------

/// `adamant::address::to_bytes(addr: address): vector<u8>`
///
/// Convert an [`Address`] to its 32-byte canonical encoding.
fn address_to_bytes(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let addr = pop_address(ctx)?;
    ctx.return_values
        .push(byte_slice_to_runtime_value(addr.as_bytes()));
    Ok(())
}

/// `adamant::address::from_bytes(bytes: vector<u8>): address`
///
/// Construct an [`Address`] from its 32-byte canonical encoding.
/// Aborts with [`InvariantViolationReason::TypeMismatchOnStack`]
/// if the input is not exactly 32 bytes — Move's type system
/// pins `vector<u8>` length at runtime; the verifier-side check
/// is residual.
fn address_from_bytes(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let bytes = pop_byte_vector(ctx)?;
    let arr: [u8; 32] = bytes
        .as_slice()
        .try_into()
        .map_err(|_| VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        })?;
    ctx.return_values
        .push(RuntimeValue::Address(Address::from_bytes(arr)));
    Ok(())
}

/// `adamant::address::equals(a: address, b: address): bool`
///
/// Byte-equality check. Could be expressed in pure Move bytecode,
/// but ships native for symmetry with the rest of the address
/// helper set and to avoid a per-byte loop in deployed bytecode.
fn address_equals(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let b = pop_address(ctx)?;
    let a = pop_address(ctx)?;
    ctx.return_values.push(RuntimeValue::Bool(a == b));
    Ok(())
}

// ---------------------------------------------------------------
// adamant::tx_context native handlers (Phase 5/6.8.C)
// ---------------------------------------------------------------

/// `adamant::tx_context::sender(): address`
///
/// Returns the cleartext address of the transaction's
/// `authorising_account` per whitepaper §6.0.2 + §6.5 amendment.
///
/// # Errors
///
/// - [`InvariantViolationReason::NativeContextMissingTxContext`]
///   if invoked without a transaction context.
/// - [`InvariantViolationReason::ShieldedSenderRequiresPrivacyLayer`]
///   if `authorising_account` is shielded; cleartext-resolution for
///   shielded senders is §7-territory.
fn tx_context_sender(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let tx_ctx = ctx.tx_context.as_ref().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::NativeContextMissingTxContext,
    })?;
    let addr = match &tx_ctx.tx_body.authorising_account {
        crate::transaction::AccountRef::Cleartext(a) => *a,
        crate::transaction::AccountRef::Shielded(_) => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::ShieldedSenderRequiresPrivacyLayer,
            })
        }
    };
    ctx.return_values.push(RuntimeValue::Address(addr));
    Ok(())
}

/// `adamant::tx_context::tx_hash(): vector<u8>`
///
/// Returns the transaction's `TxHash` as a 32-byte vector per
/// whitepaper §6.0.4. Read-only access to the executing
/// transaction's hash; useful for protocol-level identifier
/// derivation in user code (e.g., deterministic salts).
fn tx_context_tx_hash(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let tx_ctx = ctx.tx_context.as_ref().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::NativeContextMissingTxContext,
    })?;
    let bytes = tx_ctx.tx_hash.to_bytes();
    ctx.return_values.push(byte_slice_to_runtime_value(&bytes));
    Ok(())
}

/// `adamant::tx_context::gas_remaining(dimension: u8): u64`
///
/// Returns the remaining gas budget for the specified dimension
/// per whitepaper §6.3.1. Pops a u8 dimension tag (0x00 =
/// Computation, 0x01 = Storage, ..., 0x05 = `ProofGeneration`) and
/// pushes the remaining u64.
///
/// # Errors
///
/// - [`InvariantViolationReason::TypeMismatchOnStack`] for non-u8
///   arg or out-of-range dimension byte.
fn tx_context_gas_remaining(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let RuntimeValue::U8(dim_byte) = pop_arg(ctx)? else {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        });
    };
    let dimension = match dim_byte {
        0x00 => crate::bytecode::GasDimension::Computation,
        0x01 => crate::bytecode::GasDimension::Storage,
        0x02 => crate::bytecode::GasDimension::Rent,
        0x03 => crate::bytecode::GasDimension::Bandwidth,
        0x04 => crate::bytecode::GasDimension::ProofVerification,
        0x05 => crate::bytecode::GasDimension::ProofGeneration,
        _ => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::TypeMismatchOnStack,
            })
        }
    };
    let remaining = ctx.state.remaining_gas(dimension);
    ctx.return_values.push(RuntimeValue::U64(remaining));
    Ok(())
}

// ---------------------------------------------------------------
// adamant::module native handlers (Phase 5/6.8.C)
// ---------------------------------------------------------------

/// `adamant::module::deploy(bytecode: vector<u8>): address`
///
/// Deploy a new module per whitepaper §6.4.1. Validates via
/// [`crate::validator::deploy_validate`] (single-module pipeline +
/// cross-module Rule 3), constructs the new `Module` Object per
/// the §6.4.1 amendment, and stages its creation in the
/// transaction's state buffer. Returns the new Module's
/// `ObjectId` as a `vector<u8>`-encoded `address`.
///
/// # Errors
///
/// - [`InvariantViolationReason::NativeContextMissingTxContext`]
///   if invoked without a transaction context.
/// - [`InvariantViolationReason::ShieldedSenderRequiresPrivacyLayer`]
///   if the deploying account is shielded; module deployment from
///   shielded sender is §7-territory.
/// - [`VMError::ModuleDeploymentFailed`] wrapping the validator
///   error if `deploy_validate` rejects.
fn module_deploy(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let bytecode = pop_byte_vector(ctx)?;
    let tx_ctx = ctx.tx_context.as_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::NativeContextMissingTxContext,
    })?;

    // 1. Resolve deploying account from authorising_account.
    let creator = match &tx_ctx.tx_body.authorising_account {
        crate::transaction::AccountRef::Cleartext(a) => *a,
        crate::transaction::AccountRef::Shielded(_) => {
            return Err(VMError::InvariantViolation {
                reason: InvariantViolationReason::ShieldedSenderRequiresPrivacyLayer,
            })
        }
    };

    // 2. Validate via deploy_validate (single-module + cross-module Rule 3).
    let module = crate::validator::deploy_validate(
        &bytecode,
        tx_ctx.verifier_config,
        tx_ctx.module_resolver,
    )
    .map_err(|e| VMError::ModuleDeploymentFailed { error: Box::new(e) })?;

    // 3. Decode mutability from b"adamant.mutability" metadata
    //    (already structurally validated by Rule 1; this re-decodes
    //    it for the new Object's mutability field).
    let mutability = decode_mutability_from_metadata(&module)?;

    // 4. Derive the new Module's ObjectId per §5.1.1 from
    //    (tx_hash, deploying_account, deploy_index).
    let object_id = adamant_state::derive_object_id(tx_ctx.tx_hash, &creator, tx_ctx.deploy_index);
    tx_ctx.deploy_index += 1;

    // 5. Construct the Module Object per §6.4.1 amendment.
    let contents = adamant_types::Contents::from_bytes(&bytecode).map_err(|_| {
        VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        }
    })?;
    let module_obj = adamant_types::Object {
        id: object_id,
        type_id: stdlib_module_type_id(),
        owner: adamant_types::Ownership::Address(creator),
        mutability,
        lifecycle: adamant_types::Lifecycle::Active,
        contents,
        version: 1,
        metadata: adamant_types::ObjectMetadata {
            created_at_height: 0,
            last_modified_height: 0,
            creator,
            storage_rent_paid_through: 0,
            // Proof commitment for the deployed module is the
            // §3.9.2 KZG commitment to the bytecode; production
            // construction lands at Phase 6 alongside KZG
            // dispatch + EthPoT setup ingestion. Phase 5/6.8.C
            // ships zero-bytes placeholder consistent with the
            // §7-deferred shielded-deployment path.
            proof_commitment: adamant_types::ProofCommitment::from_bytes(
                [0u8; adamant_types::metadata::PROOF_COMMITMENT_BYTES],
            ),
        },
    };

    // 6. Stage module-object creation in the transaction state buffer.
    tx_ctx.state_buffer.record_create(module_obj);

    // 7. Return the new module's ObjectId as a vector<u8>.
    let id_bytes = object_id.to_bytes();
    ctx.return_values
        .push(byte_slice_to_runtime_value(&id_bytes));
    Ok(())
}

/// Genesis-fixed `TypeId` for the `adamant::module::Module` type
/// per whitepaper §6.4.1 amendment.
///
/// Computed as `sha3_256_tagged(TYPE_ID_STDLIB, BCS((STDLIB_ADDRESS,
/// "module", "Module")))` — same shape as account-address /
/// object-id derivations. Phase 5/6.8.C ships a placeholder pinned
/// at all-zero bytes; the production derivation lands when the
/// `TypeId`-derivation function ships in adamant-types alongside
/// the genesis stdlib type registry. Pre-mainnet hardening item.
fn stdlib_module_type_id() -> adamant_types::TypeId {
    adamant_types::TypeId::from_bytes([0u8; 32])
}

const MUTABILITY_METADATA_KEY: &[u8] = b"adamant.mutability";

/// Decode the `b"adamant.mutability"` metadata entry's value into
/// a [`adamant_types::Mutability`]. Validator Rule 1 ensures the
/// metadata entry exists and has a single well-formed value;
/// re-decoding here is a residual binding.
fn decode_mutability_from_metadata(
    module: &crate::module::AdamantCompiledModule,
) -> Result<adamant_types::Mutability, VMError> {
    let entry = module
        .metadata
        .iter()
        .find(|m| m.key == MUTABILITY_METADATA_KEY)
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        })?;
    bcs::from_bytes(&entry.value).map_err(|_| VMError::InvariantViolation {
        reason: InvariantViolationReason::TypeMismatchOnStack,
    })
}

// ---------------------------------------------------------------
// adamant::object native handlers (Phase 5/6.8.C)
// ---------------------------------------------------------------

/// `adamant::object::transfer(obj_id: vector<u8>, recipient: address): ()`
///
/// Stage an ownership transfer for the object with the given id
/// to the recipient address. Loads the current object via
/// `state_view`, asserts ownership rules, increments version,
/// records the update in the state buffer.
fn object_transfer(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let recipient = pop_address(ctx)?;
    let id_bytes = pop_byte_vector(ctx)?;
    let id = object_id_from_bytes(&id_bytes)?;
    let tx_ctx = ctx.tx_context.as_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::NativeContextMissingTxContext,
    })?;
    let mut object = load_object_for_mutation(tx_ctx, id)?;
    object.owner = adamant_types::Ownership::Address(recipient);
    object.version += 1;
    tx_ctx.state_buffer.record_update(object);
    Ok(())
}

/// `adamant::object::freeze(obj_id: vector<u8>): ()`
///
/// Transition the object's lifecycle from `Active` to `Frozen`
/// per whitepaper §5.4.1.
fn object_freeze(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let id_bytes = pop_byte_vector(ctx)?;
    let id = object_id_from_bytes(&id_bytes)?;
    let tx_ctx = ctx.tx_context.as_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::NativeContextMissingTxContext,
    })?;
    let mut object = load_object_for_mutation(tx_ctx, id)?;
    if !matches!(object.lifecycle, adamant_types::Lifecycle::Active) {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        });
    }
    object.lifecycle = adamant_types::Lifecycle::Frozen;
    object.version += 1;
    tx_ctx.state_buffer.record_update(object);
    Ok(())
}

/// `adamant::object::share(obj_id: vector<u8>): ()`
///
/// Transition the object's ownership to `Shared` per whitepaper
/// §5.1.3. Once shared, ownership cannot return to `Address` per
/// §5.1.3's transition rules.
fn object_share(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let id_bytes = pop_byte_vector(ctx)?;
    let id = object_id_from_bytes(&id_bytes)?;
    let tx_ctx = ctx.tx_context.as_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::NativeContextMissingTxContext,
    })?;
    let mut object = load_object_for_mutation(tx_ctx, id)?;
    object.owner = adamant_types::Ownership::Shared;
    object.version += 1;
    tx_ctx.state_buffer.record_update(object);
    Ok(())
}

/// `adamant::object::archive(obj_id: vector<u8>): ()`
///
/// Transition the object's lifecycle to `Archived` per
/// whitepaper §5.4 / §5.4.1.
fn object_archive(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let id_bytes = pop_byte_vector(ctx)?;
    let id = object_id_from_bytes(&id_bytes)?;
    let tx_ctx = ctx.tx_context.as_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::NativeContextMissingTxContext,
    })?;
    let mut object = load_object_for_mutation(tx_ctx, id)?;
    object.lifecycle = adamant_types::Lifecycle::Archived;
    object.version += 1;
    tx_ctx.state_buffer.record_update(object);
    Ok(())
}

/// `adamant::object::restore(obj_id: vector<u8>): ()`
///
/// Restore an `Archived` object to `Active` per whitepaper §5.4
/// / §5.4.1.
fn object_restore(ctx: &mut NativeContext<'_>) -> Result<(), VMError> {
    let id_bytes = pop_byte_vector(ctx)?;
    let id = object_id_from_bytes(&id_bytes)?;
    let tx_ctx = ctx.tx_context.as_mut().ok_or(VMError::InvariantViolation {
        reason: InvariantViolationReason::NativeContextMissingTxContext,
    })?;
    let mut object = load_object_for_mutation(tx_ctx, id)?;
    if !matches!(object.lifecycle, adamant_types::Lifecycle::Archived) {
        return Err(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        });
    }
    object.lifecycle = adamant_types::Lifecycle::Active;
    object.version += 1;
    tx_ctx.state_buffer.record_update(object);
    Ok(())
}

/// Convert `vector<u8>` argument bytes into an [`adamant_types::ObjectId`].
fn object_id_from_bytes(bytes: &[u8]) -> Result<adamant_types::ObjectId, VMError> {
    let arr: [u8; 32] = bytes.try_into().map_err(|_| VMError::InvariantViolation {
        reason: InvariantViolationReason::TypeMismatchOnStack,
    })?;
    Ok(adamant_types::ObjectId::from_bytes(arr))
}

/// Load an object for mutation, validating it's loaded at its
/// declared read-set version. Used by the `object::*` handlers as
/// the residual binding for §6.0.2 read-set version pinning.
fn load_object_for_mutation(
    tx_ctx: &crate::runtime::TransactionContext<'_>,
    id: adamant_types::ObjectId,
) -> Result<adamant_types::Object, VMError> {
    let expected_version = tx_ctx
        .tx_body
        .read_set
        .iter()
        .find_map(|(rid, v)| if *rid == id { Some(*v) } else { None })
        .ok_or(VMError::InvariantViolation {
            reason: InvariantViolationReason::TypeMismatchOnStack,
        })?;
    tx_ctx
        .state_view
        .load_object(&id, expected_version)
        .map_err(VMError::Load)
}

// ---------------------------------------------------------------
// Genesis-fixed registry constructor
// ---------------------------------------------------------------

fn ident(s: &str) -> Identifier {
    Identifier::new(s)
        .unwrap_or_else(|_| panic!("stdlib identifier `{s}` must be a valid Adamant identifier"))
}

fn key(module: &str, function: &str) -> NativeKey {
    NativeKey::new(STDLIB_ADDRESS, ident(module), ident(function))
}

/// Construct the genesis-fixed [`NativeRegistry`] with every
/// stdlib native handler shipped at Phase 5/6.8.B registered
/// under its canonical [`NativeKey`].
///
/// Per whitepaper §6.5 amendment, the mapping is genesis-fixed:
/// adding or removing a registered handler is a hard fork.
/// Future Phase 5/6.8 sub-arcs extend the registry with
/// chain-state-mutating handlers (`adamant::module::deploy`,
/// `adamant::object::*`, `adamant::tx_context::*`) once the
/// [`NativeContext`] is extended with the additional state
/// references those handlers need.
#[must_use]
pub fn genesis_native_registry() -> NativeRegistry {
    let mut registry = NativeRegistry::new();

    // adamant::hash
    let prev = registry.register(key("hash", "sha3_256"), hash_sha3_256);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::hash::sha3_256"
    );
    let prev = registry.register(key("hash", "blake3"), hash_blake3);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::hash::blake3"
    );

    // adamant::signature
    let prev = registry.register(key("signature", "verify_ed25519"), signature_verify_ed25519);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::signature::verify_ed25519"
    );
    let prev = registry.register(
        key("signature", "verify_ml_dsa_65"),
        signature_verify_ml_dsa_65,
    );
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::signature::verify_ml_dsa_65"
    );

    // adamant::address
    let prev = registry.register(key("address", "to_bytes"), address_to_bytes);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::address::to_bytes"
    );
    let prev = registry.register(key("address", "from_bytes"), address_from_bytes);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::address::from_bytes"
    );
    let prev = registry.register(key("address", "equals"), address_equals);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::address::equals"
    );

    // adamant::tx_context (Phase 5/6.8.C)
    let prev = registry.register(key("tx_context", "sender"), tx_context_sender);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::tx_context::sender"
    );
    let prev = registry.register(key("tx_context", "tx_hash"), tx_context_tx_hash);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::tx_context::tx_hash"
    );
    let prev = registry.register(key("tx_context", "gas_remaining"), tx_context_gas_remaining);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::tx_context::gas_remaining"
    );

    // adamant::module (Phase 5/6.8.C)
    let prev = registry.register(key("module", "deploy"), module_deploy);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::module::deploy"
    );

    // adamant::object (Phase 5/6.8.C)
    let prev = registry.register(key("object", "transfer"), object_transfer);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::object::transfer"
    );
    let prev = registry.register(key("object", "freeze"), object_freeze);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::object::freeze"
    );
    let prev = registry.register(key("object", "share"), object_share);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::object::share"
    );
    let prev = registry.register(key("object", "archive"), object_archive);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::object::archive"
    );
    let prev = registry.register(key("object", "restore"), object_restore);
    debug_assert!(
        prev.is_none(),
        "duplicate registration: adamant::object::restore"
    );

    registry
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::module::AdamantCompiledModule;
    use crate::runtime::interpreter::InterpreterState;
    use adamant_crypto::sig_classical::SigningKey as Ed25519SigningKey;
    use adamant_crypto::sig_pq::SigningKey as MlDsaSigningKey;

    fn empty_module() -> AdamantCompiledModule {
        AdamantCompiledModule::default()
    }

    fn make_ctx<'a>(
        state: &'a mut InterpreterState,
        module: &'a AdamantCompiledModule,
        args: Vec<RuntimeValue>,
    ) -> NativeContext<'a> {
        NativeContext::new(state, module, args)
    }

    fn byte_vec_arg(bytes: &[u8]) -> RuntimeValue {
        byte_slice_to_runtime_value(bytes)
    }

    // ---------- registry shape ----------

    #[test]
    fn genesis_registry_has_expected_handler_count() {
        let registry = genesis_native_registry();
        // 2 hash + 2 signature + 3 address (5/6.8.B)
        // + 3 tx_context + 1 module + 5 object (5/6.8.C)
        // = 16 handlers.
        assert_eq!(registry.len(), 16);
    }

    #[test]
    fn genesis_registry_resolves_each_5_8_b_handler() {
        let registry = genesis_native_registry();
        for (m, f) in [
            ("hash", "sha3_256"),
            ("hash", "blake3"),
            ("signature", "verify_ed25519"),
            ("signature", "verify_ml_dsa_65"),
            ("address", "to_bytes"),
            ("address", "from_bytes"),
            ("address", "equals"),
        ] {
            assert!(
                registry.lookup(&key(m, f)).is_some(),
                "missing handler: adamant::{m}::{f}"
            );
        }
    }

    // ---------- hash ----------

    #[test]
    fn sha3_256_handler_matches_adamant_crypto_kat() {
        let mut state = InterpreterState::new();
        let module = empty_module();
        let input = b"adamant".to_vec();
        let mut ctx = make_ctx(&mut state, &module, vec![byte_vec_arg(&input)]);
        hash_sha3_256(&mut ctx).expect("ok");
        assert_eq!(ctx.return_values.len(), 1);
        let bytes = into_byte_vec(ctx.return_values.into_iter().next().unwrap()).unwrap();
        assert_eq!(bytes.as_slice(), &hash::sha3_256_plain(&input));
    }

    #[test]
    fn blake3_handler_matches_adamant_crypto_kat() {
        let mut state = InterpreterState::new();
        let module = empty_module();
        let input = b"adamant".to_vec();
        let mut ctx = make_ctx(&mut state, &module, vec![byte_vec_arg(&input)]);
        hash_blake3(&mut ctx).expect("ok");
        let bytes = into_byte_vec(ctx.return_values.into_iter().next().unwrap()).unwrap();
        assert_eq!(bytes.as_slice(), &hash::blake3(&input));
    }

    #[test]
    fn sha3_256_handler_rejects_non_byte_vector_arg() {
        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(&mut state, &module, vec![RuntimeValue::U64(7)]);
        let result = hash_sha3_256(&mut ctx);
        assert!(matches!(result, Err(VMError::InvariantViolation { .. })));
    }

    // ---------- signature ----------

    #[test]
    fn ed25519_handler_returns_true_on_valid_sig() {
        let seed = [0x42_u8; 32];
        let signing = Ed25519SigningKey::from_seed(&seed);
        let verifying = signing.verifying_key();
        let message = b"adamant message".to_vec();
        let sig = signing.sign(&message);

        let mut state = InterpreterState::new();
        let module = empty_module();
        // Args in declaration order (signature, message, public_key)
        // — args[0] is first parameter, popped LIFO.
        let mut ctx = make_ctx(
            &mut state,
            &module,
            vec![
                byte_vec_arg(&sig.to_bytes()),
                byte_vec_arg(&message),
                byte_vec_arg(&verifying.to_bytes()),
            ],
        );
        signature_verify_ed25519(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Bool(true)
        ));
    }

    #[test]
    fn ed25519_handler_returns_false_on_tampered_message() {
        let seed = [0x42_u8; 32];
        let signing = Ed25519SigningKey::from_seed(&seed);
        let verifying = signing.verifying_key();
        let sig = signing.sign(b"original");

        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(
            &mut state,
            &module,
            vec![
                byte_vec_arg(&sig.to_bytes()),
                byte_vec_arg(b"tampered"),
                byte_vec_arg(&verifying.to_bytes()),
            ],
        );
        signature_verify_ed25519(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Bool(false)
        ));
    }

    #[test]
    fn ed25519_handler_returns_false_on_malformed_sig_length() {
        let seed = [0x42_u8; 32];
        let signing = Ed25519SigningKey::from_seed(&seed);
        let verifying = signing.verifying_key();

        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(
            &mut state,
            &module,
            vec![
                byte_vec_arg(&[0u8; 10]), // wrong length
                byte_vec_arg(b"msg"),
                byte_vec_arg(&verifying.to_bytes()),
            ],
        );
        signature_verify_ed25519(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Bool(false)
        ));
    }

    #[test]
    fn ml_dsa_65_handler_returns_true_on_valid_sig() {
        let seed = [0x9a_u8; 32];
        let signing = MlDsaSigningKey::from_seed(&seed);
        let verifying = signing.verifying_key();
        let message = b"adamant pq message".to_vec();
        let sig = signing.sign(&message).expect("sign");

        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(
            &mut state,
            &module,
            vec![
                byte_vec_arg(&sig.to_bytes()),
                byte_vec_arg(&message),
                byte_vec_arg(&verifying.to_bytes()),
            ],
        );
        signature_verify_ml_dsa_65(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Bool(true)
        ));
    }

    #[test]
    fn ml_dsa_65_handler_returns_false_on_malformed_sig_length() {
        // Audit-pass parity with the ed25519 malformed-length test.
        // ML-DSA-65 signature is 3309 bytes per FIPS 204; passing
        // any other length must return Bool(false), not abort.
        let seed = [0x9a_u8; 32];
        let signing = MlDsaSigningKey::from_seed(&seed);
        let verifying = signing.verifying_key();

        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(
            &mut state,
            &module,
            vec![
                byte_vec_arg(&[0u8; 100]), // wrong length
                byte_vec_arg(b"msg"),
                byte_vec_arg(&verifying.to_bytes()),
            ],
        );
        signature_verify_ml_dsa_65(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Bool(false)
        ));
    }

    #[test]
    fn ml_dsa_65_handler_returns_false_on_malformed_pk_length() {
        // Audit-pass parity: malformed public-key length must
        // return Bool(false), not abort.
        let seed = [0x9a_u8; 32];
        let signing = MlDsaSigningKey::from_seed(&seed);
        let sig = signing.sign(b"msg").expect("sign");

        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(
            &mut state,
            &module,
            vec![
                byte_vec_arg(&sig.to_bytes()),
                byte_vec_arg(b"msg"),
                byte_vec_arg(&[0u8; 100]), // wrong pk length
            ],
        );
        signature_verify_ml_dsa_65(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Bool(false)
        ));
    }

    #[test]
    fn ml_dsa_65_handler_returns_false_on_tampered_message() {
        let seed = [0x9a_u8; 32];
        let signing = MlDsaSigningKey::from_seed(&seed);
        let verifying = signing.verifying_key();
        let sig = signing.sign(b"original").expect("sign");

        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(
            &mut state,
            &module,
            vec![
                byte_vec_arg(&sig.to_bytes()),
                byte_vec_arg(b"tampered"),
                byte_vec_arg(&verifying.to_bytes()),
            ],
        );
        signature_verify_ml_dsa_65(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Bool(false)
        ));
    }

    // ---------- address ----------

    #[test]
    fn address_to_bytes_returns_32_byte_vector() {
        let addr = Address::from_bytes([0xab; 32]);
        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(&mut state, &module, vec![RuntimeValue::Address(addr)]);
        address_to_bytes(&mut ctx).expect("ok");
        let bytes = into_byte_vec(ctx.return_values.into_iter().next().unwrap()).unwrap();
        assert_eq!(bytes, vec![0xab; 32]);
    }

    #[test]
    fn address_from_bytes_round_trips() {
        let addr = Address::from_bytes([0x77; 32]);
        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(&mut state, &module, vec![byte_vec_arg(addr.as_bytes())]);
        address_from_bytes(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Address(a) if *a == addr
        ));
    }

    #[test]
    fn address_from_bytes_rejects_wrong_length() {
        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(&mut state, &module, vec![byte_vec_arg(&[0xff; 31])]);
        let result = address_from_bytes(&mut ctx);
        assert!(matches!(result, Err(VMError::InvariantViolation { .. })));
    }

    #[test]
    fn address_equals_returns_true_for_identical() {
        let addr = Address::from_bytes([0x10; 32]);
        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(
            &mut state,
            &module,
            vec![RuntimeValue::Address(addr), RuntimeValue::Address(addr)],
        );
        address_equals(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Bool(true)
        ));
    }

    #[test]
    fn address_equals_returns_false_for_distinct() {
        let mut state = InterpreterState::new();
        let module = empty_module();
        let mut ctx = make_ctx(
            &mut state,
            &module,
            vec![
                RuntimeValue::Address(Address::from_bytes([0x10; 32])),
                RuntimeValue::Address(Address::from_bytes([0x20; 32])),
            ],
        );
        address_equals(&mut ctx).expect("ok");
        assert!(matches!(
            ctx.return_values.first().unwrap(),
            RuntimeValue::Bool(false)
        ));
    }
}
