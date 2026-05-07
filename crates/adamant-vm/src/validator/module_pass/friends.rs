//! Module-level pass: friend-declaration validation
//! (whitepaper §6.2.1.8 step 3).
//!
//! Forked from `vendor/move-bytecode-verifier/src/friends.rs`
//! at Sui-Move tag `mainnet-v1.66.2` (commit
//! `a9a6825eaf6273cc819ee3bcf65fd4909f7624a9`). See
//! `validator/module_pass/PROVENANCE.md` for the deviation
//! list. Summary:
//!
//! - Operates on [`AdamantCompiledModule`] rather than Sui's
//!   `CompiledModule`. The friend-declarations table is byte-
//!   identical between the two per Phase 5/5b.1b's bytecode-
//!   format fork.
//! - Returns typed [`AdamantValidationError`] variants
//!   (`SelfFriendDeclaration`,
//!   `CrossAccountFriendDeclaration`) rather than upstream's
//!   `PartialVMError`/`StatusCode`.
//! - Direct algorithmic port (no Adamant-native algorithm
//!   replacement; the structural shape of the pass carries
//!   over byte-faithfully).
//!
//! Two assertions per module:
//!
//! 1. **No self-friend.** The module's own `self_handle` does
//!    not appear in `friend_decls`.
//! 2. **No cross-account friends.** Every friend declaration's
//!    address (resolved through `address_identifiers`) equals
//!    the module's own self-address.
//!
//! Upstream notes the cross-account check is "a policy
//! decision rather than a technical requirement... we may
//! consider lifting this limitation in the future." Adamant
//! inherits the policy under its own audit per the resistant-
//! proof posture (whitepaper §6.2.1.8); future relaxation
//! requires a deliberate Adamant-side decision rather than
//! tracking a Sui upstream change.
//!
//! # Dead-code allow (transient)
//!
//! Phase 5/5b.2 B-5 wires this pass into
//! [`crate::validator::verify_module`]. Until B-5 lands, the
//! pass is reachable only from inline tests and Layer B
//! cross-validation; the lib build sees the entry point as
//! dead. The module-level `dead_code` allow is removed when
//! B-5 wires the pass.

#![allow(dead_code, reason = "wired into verify_module() in Phase 5/5b.2 B-5")]

use adamant_bytecode_format::{ModuleHandle, TableIndex};

use crate::module::AdamantCompiledModule;

use super::super::error::AdamantValidationError;

/// Verify the module's friend declarations against §6.2.1.8
/// step 3 (`module_pass::friends`).
///
/// Eager-error semantics: returns the first violation
/// encountered. The self-friend check fires before any
/// cross-account check (matches upstream order).
pub(in crate::validator) fn verify(
    module: &AdamantCompiledModule,
) -> Result<(), AdamantValidationError> {
    let self_handle = self_handle(module);

    if module.friend_decls.contains(self_handle) {
        return Err(AdamantValidationError::SelfFriendDeclaration);
    }

    let self_address = module.address_identifiers[self_handle.address.0 as usize];
    for (idx, friend) in module.friend_decls.iter().enumerate() {
        let friend_address = module.address_identifiers[friend.address.0 as usize];
        if friend_address != self_address {
            return Err(AdamantValidationError::CrossAccountFriendDeclaration {
                idx: TableIndex::try_from(idx).expect(
                    "friend_decls count exceeds u16; binary format precludes this \
                         (TABLE_INDEX_MAX = u16::MAX)",
                ),
                foreign_address: friend_address,
            });
        }
    }

    Ok(())
}

/// Look up the module's `self_handle` in `module_handles`.
fn self_handle(module: &AdamantCompiledModule) -> &ModuleHandle {
    &module.module_handles[module.self_module_handle_idx.0 as usize]
}

#[cfg(test)]
mod tests {
    use adamant_bytecode_format::{
        AddressIdentifierIndex, Identifier, IdentifierIndex, ModuleHandle, ModuleHandleIndex,
    };
    use adamant_types::Address as AccountAddress;

    use crate::module::AdamantCompiledModule;

    use super::super::super::error::AdamantValidationError;
    use super::super::test_helpers::assert_pass_parity;
    use super::verify;

    /// Build a fixture module shell with the self-handle
    /// referencing identifier 0 ("M") and address 0 ([0u8; 32]).
    /// Standard "module-self-identity" wiring: `module_handles[0]`
    /// is the self-handle; `address_identifiers[0]` carries the
    /// module's own address; `identifiers[0]` carries the
    /// module's own name. Friend-fixture builders can extend
    /// the identifier and address pools without breaking the
    /// self-handle wiring.
    fn empty_module() -> AdamantCompiledModule {
        AdamantCompiledModule {
            self_module_handle_idx: ModuleHandleIndex(0),
            module_handles: vec![ModuleHandle {
                address: AddressIdentifierIndex(0),
                name: IdentifierIndex(0),
            }],
            identifiers: vec![Identifier::new("M").unwrap()],
            address_identifiers: vec![AccountAddress::from_bytes([0u8; 32])],
            ..AdamantCompiledModule::default()
        }
    }

    /// Extend a module with a second identifier (`"F"`) at
    /// index 1 and a friend declaration pointing at it under
    /// the same address as `self`. Returns the modified module.
    fn with_valid_same_account_friend(mut m: AdamantCompiledModule) -> AdamantCompiledModule {
        m.identifiers.push(Identifier::new("F").unwrap());
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        m
    }

    /// Extend a module with a friend declaration that exactly
    /// matches `self_handle` (same address index, same name
    /// index). Triggers Rule 1 (self-friend).
    fn with_self_friend(mut m: AdamantCompiledModule) -> AdamantCompiledModule {
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        m
    }

    /// Extend a module with a second address (foreign), a
    /// second identifier (`"F"`), and a friend declaration
    /// pointing at the foreign address. Triggers Rule 2
    /// (cross-account friend).
    fn with_cross_account_friend(mut m: AdamantCompiledModule) -> AdamantCompiledModule {
        m.address_identifiers
            .push(AccountAddress::from_bytes([0xAA; 32]));
        m.identifiers.push(Identifier::new("F").unwrap());
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(1),
            name: IdentifierIndex(1),
        });
        m
    }

    // --- Layer A: positive cases ---

    #[test]
    fn empty_friend_decls_passes() {
        let m = empty_module();
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn valid_same_account_friend_passes() {
        let m = with_valid_same_account_friend(empty_module());
        assert!(verify(&m).is_ok());
    }

    #[test]
    fn multiple_valid_same_account_friends_pass() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("F1").unwrap());
        m.identifiers.push(Identifier::new("F2").unwrap());
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(2),
        });
        assert!(verify(&m).is_ok());
    }

    // --- Layer A: negative cases ---

    #[test]
    fn rejects_self_friend() {
        let m = with_self_friend(empty_module());
        match verify(&m) {
            Err(AdamantValidationError::SelfFriendDeclaration) => {}
            other => panic!("expected SelfFriendDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn rejects_cross_account_friend() {
        let m = with_cross_account_friend(empty_module());
        match verify(&m) {
            Err(AdamantValidationError::CrossAccountFriendDeclaration {
                idx: 0,
                foreign_address,
            }) => {
                assert_eq!(foreign_address.as_bytes(), &[0xAA; 32]);
            }
            other => panic!("expected CrossAccountFriendDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn self_friend_wins_over_cross_account_eager_error() {
        // Module has both a self-friend (decl 0) and a cross-
        // account friend (decl 1). Eager-error: self-friend
        // is checked first via `friend_decls.contains` — it
        // fires regardless of declaration order.
        let mut m = empty_module();
        m.address_identifiers
            .push(AccountAddress::from_bytes([0xAA; 32]));
        m.identifiers.push(Identifier::new("F").unwrap());
        // Self-friend first.
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(0),
        });
        // Cross-account friend second.
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(1),
            name: IdentifierIndex(1),
        });
        match verify(&m) {
            Err(AdamantValidationError::SelfFriendDeclaration) => {}
            other => panic!("expected SelfFriendDeclaration, got {other:?}"),
        }
    }

    #[test]
    fn cross_account_idx_reports_first_offender() {
        // First friend decl: valid same-account. Second:
        // cross-account. Eager-error reports decl 1 (lowest-
        // index offender).
        let mut m = empty_module();
        m.address_identifiers
            .push(AccountAddress::from_bytes([0xAA; 32]));
        m.identifiers.push(Identifier::new("F1").unwrap());
        m.identifiers.push(Identifier::new("F2").unwrap());
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(1),
            name: IdentifierIndex(2),
        });
        match verify(&m) {
            Err(AdamantValidationError::CrossAccountFriendDeclaration {
                idx: 1,
                foreign_address,
            }) => {
                assert_eq!(foreign_address.as_bytes(), &[0xAA; 32]);
            }
            other => panic!("expected CrossAccountFriendDeclaration {{ idx: 1 }}, got {other:?}"),
        }
    }

    // --- Layer B: cross-validation against vendored Sui ---
    //
    // For each fixture below, run Adamant's `verify` and Sui's
    // `move_bytecode_verifier::friends::verify_module` over
    // the same module (after BCS round-trip via to_sui_module),
    // assert accept/reject parity via the shared
    // `assert_pass_parity` helper extracted at B-2.2.
    //
    // Coverage target (per the B-2.2 plan):
    //   - 3 accept-parity (no friends, single same-account
    //     friend, multiple same-account friends)
    //   - 2 reject-parity per error variant (self-friend,
    //     cross-account friend)

    fn cross_validate_friends_pass(m: &AdamantCompiledModule) {
        let adamant_result = verify(m);
        let sui_module = m
            .to_sui_module()
            .expect("test fixture has no Adamant extensions; to_sui_module must succeed");
        let sui_result = move_bytecode_verifier::friends::verify_module(&sui_module);
        assert_pass_parity("friends", adamant_result, sui_result);
    }

    #[test]
    fn cross_validation_accepts_module_with_no_friends() {
        let m = empty_module();
        cross_validate_friends_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_single_same_account_friend() {
        let m = with_valid_same_account_friend(empty_module());
        cross_validate_friends_pass(&m);
    }

    #[test]
    fn cross_validation_accepts_multiple_same_account_friends() {
        let mut m = empty_module();
        m.identifiers.push(Identifier::new("F1").unwrap());
        m.identifiers.push(Identifier::new("F2").unwrap());
        m.identifiers.push(Identifier::new("F3").unwrap());
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(1),
        });
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(2),
        });
        m.friend_decls.push(ModuleHandle {
            address: AddressIdentifierIndex(0),
            name: IdentifierIndex(3),
        });
        cross_validate_friends_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_self_friend() {
        let m = with_self_friend(empty_module());
        cross_validate_friends_pass(&m);
    }

    #[test]
    fn cross_validation_rejects_cross_account_friend() {
        let m = with_cross_account_friend(empty_module());
        cross_validate_friends_pass(&m);
    }
}
