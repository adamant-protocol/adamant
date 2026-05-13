//! Phase 9.4 end-to-end CLI integration tests.
//!
//! Exercises the operator-CLI surface at the binary-integration
//! tier per whitepaper §8.1.2. Each test wires the
//! [`adamant_cli::execute`] public API through to the
//! consensus-tier `ValidatorPublicKeys` + the cryptographic
//! BLS keygen, exercising the operator-tool flow end-to-end.

use adamant_cli::{execute, parse_args, CliError, Command, HELP_TEXT};
use adamant_consensus::{
    ValidatorPublicKeys, BLS_PUBLIC_KEY_BYTES, BLS_SIGNATURE_BYTES, ED25519_PUBLIC_KEY_BYTES,
    ML_DSA_PUBLIC_KEY_BYTES,
};

/// `version` round-trip: parse + execute the version command,
/// produce non-empty output mentioning Adamant.
#[test]
fn version_command_round_trip() {
    let cmd = parse_args(&["version".to_string()]).expect("parse");
    assert_eq!(cmd, Command::Version);
    let out = execute(&cmd).expect("execute");
    assert!(out.stdout.contains("adamant-cli"));
}

/// `--version` flag also parses to the version command.
#[test]
fn version_flag_alias() {
    let cmd = parse_args(&["--version".to_string()]).expect("parse");
    assert_eq!(cmd, Command::Version);
}

/// `-v` short flag also parses to the version command.
#[test]
fn version_short_flag_alias() {
    let cmd = parse_args(&["-v".to_string()]).expect("parse");
    assert_eq!(cmd, Command::Version);
}

/// `keys generate-bls` produces a BLS keypair pair. Pinned at
/// the integration tier: the produced public-key blob has the
/// canonical 96-byte width per §3.4.3.
#[test]
fn bls_keygen_produces_canonical_widths() {
    let ikm_hex = hex::encode(vec![7u8; 32]);
    let cmd =
        parse_args(&["keys".to_string(), "generate-bls".to_string(), ikm_hex]).expect("parse");
    let out = execute(&cmd).expect("execute");

    // Parse the public-key hex out of the output (after
    // "public_hex: ").
    let pk_line = out
        .stdout
        .lines()
        .find(|l| l.starts_with("public_hex: "))
        .expect("public_hex line");
    let pk_hex = pk_line.trim_start_matches("public_hex: ");
    let pk_bytes = hex::decode(pk_hex).expect("decode");
    assert_eq!(pk_bytes.len(), BLS_PUBLIC_KEY_BYTES);

    // Secret key is also present.
    let sk_line = out
        .stdout
        .lines()
        .find(|l| l.starts_with("secret_hex: "))
        .expect("secret_hex line");
    let sk_hex = sk_line.trim_start_matches("secret_hex: ");
    assert!(hex::decode(sk_hex).is_ok());
}

/// `keys derive-validator-id` round-trip: hex-encode a
/// `ValidatorPublicKeys` bundle, derive the id through the
/// CLI, decode the output id, confirm it matches the direct
/// `ValidatorPublicKeys::derive_id` result. Pins the
/// cross-crate consistency between the CLI tool and the
/// consensus-tier derivation.
#[test]
fn derive_validator_id_matches_direct_derivation() {
    let ed25519 = [0x11; ED25519_PUBLIC_KEY_BYTES];
    let ml_dsa = [0x22; ML_DSA_PUBLIC_KEY_BYTES];
    let bls = [0x33; BLS_PUBLIC_KEY_BYTES];
    let bls_pop = [0x44; BLS_SIGNATURE_BYTES];
    let pubkeys = ValidatorPublicKeys::new(ed25519, ml_dsa, bls, bls_pop);
    let expected_id = pubkeys.derive_id();

    let cmd = Command::KeysDeriveValidatorId {
        ed25519_hex: hex::encode(ed25519),
        ml_dsa_hex: hex::encode(ml_dsa),
        bls_hex: hex::encode(bls),
        bls_pop_hex: hex::encode(bls_pop),
    };
    let out = execute(&cmd).expect("execute");

    let id_line = out
        .stdout
        .lines()
        .find(|l| l.starts_with("validator_id: "))
        .expect("validator_id line");
    let id_hex = id_line.trim_start_matches("validator_id: ");
    let id_bytes = hex::decode(id_hex).expect("decode");
    assert_eq!(id_bytes.as_slice(), expected_id.as_bytes());
}

/// `keys derive-validator-id` rejects wrong-width Ed25519
/// inputs with a typed error mentioning the component name.
/// Pins the error-shape for operator-friendly diagnostics.
#[test]
fn derive_validator_id_rejects_wrong_ed25519_width() {
    let cmd = Command::KeysDeriveValidatorId {
        ed25519_hex: hex::encode([0x11; 16]), // too short
        ml_dsa_hex: hex::encode([0x22; ML_DSA_PUBLIC_KEY_BYTES]),
        bls_hex: hex::encode([0x33; BLS_PUBLIC_KEY_BYTES]),
        bls_pop_hex: hex::encode([0x44; BLS_SIGNATURE_BYTES]),
    };
    let err = execute(&cmd).expect_err("expected width mismatch");
    match err {
        CliError::PublicKeyWidthMismatch {
            component,
            actual,
            expected,
        } => {
            assert_eq!(component, "ed25519");
            assert_eq!(actual, 16);
            assert_eq!(expected, ED25519_PUBLIC_KEY_BYTES);
        }
        other => panic!("expected PublicKeyWidthMismatch, got {other:?}"),
    }
}

/// `keys derive-validator-id` rejects wrong-width ML-DSA
/// inputs.
#[test]
fn derive_validator_id_rejects_wrong_ml_dsa_width() {
    let cmd = Command::KeysDeriveValidatorId {
        ed25519_hex: hex::encode([0x11; ED25519_PUBLIC_KEY_BYTES]),
        ml_dsa_hex: hex::encode([0x22; 100]), // wrong
        bls_hex: hex::encode([0x33; BLS_PUBLIC_KEY_BYTES]),
        bls_pop_hex: hex::encode([0x44; BLS_SIGNATURE_BYTES]),
    };
    let err = execute(&cmd).expect_err("expected width mismatch");
    assert!(matches!(
        err,
        CliError::PublicKeyWidthMismatch {
            component: "ml_dsa",
            ..
        }
    ));
}

/// `keys derive-validator-id` rejects wrong-width BLS inputs.
#[test]
fn derive_validator_id_rejects_wrong_bls_width() {
    let cmd = Command::KeysDeriveValidatorId {
        ed25519_hex: hex::encode([0x11; ED25519_PUBLIC_KEY_BYTES]),
        ml_dsa_hex: hex::encode([0x22; ML_DSA_PUBLIC_KEY_BYTES]),
        bls_hex: hex::encode([0x33; 20]), // wrong
        bls_pop_hex: hex::encode([0x44; BLS_SIGNATURE_BYTES]),
    };
    let err = execute(&cmd).expect_err("expected width mismatch");
    assert!(matches!(
        err,
        CliError::PublicKeyWidthMismatch {
            component: "bls",
            ..
        }
    ));
}

/// `keys derive-validator-id` rejects malformed hex.
#[test]
fn derive_validator_id_rejects_invalid_hex() {
    let cmd = Command::KeysDeriveValidatorId {
        ed25519_hex: "not-valid-hex!!".to_string(),
        ml_dsa_hex: hex::encode([0x22; ML_DSA_PUBLIC_KEY_BYTES]),
        bls_hex: hex::encode([0x33; BLS_PUBLIC_KEY_BYTES]),
        bls_pop_hex: hex::encode([0x44; BLS_SIGNATURE_BYTES]),
    };
    let err = execute(&cmd).expect_err("expected hex error");
    assert!(matches!(
        err,
        CliError::HexDecodeFailed {
            component: "ed25519",
            ..
        }
    ));
}

/// Unrecognised subcommand returns `None` from `parse_args`,
/// signalling the binary entry point to print `HELP_TEXT`.
#[test]
fn unrecognized_command_returns_none() {
    assert!(parse_args(&["nonsense".to_string()]).is_none());
    assert!(parse_args(&[]).is_none());
    assert!(parse_args(&["keys".to_string()]).is_none());
    assert!(parse_args(&["keys".to_string(), "nonsense".to_string()]).is_none());
}

/// `HELP_TEXT` mentions every subcommand and the §3.4 key widths
/// per the documented operator-facing reference.
#[test]
fn help_text_documents_subcommands() {
    assert!(HELP_TEXT.contains("version"));
    assert!(HELP_TEXT.contains("keys generate-bls"));
    assert!(HELP_TEXT.contains("keys derive-validator-id"));
    assert!(HELP_TEXT.contains("32 / 1952 / 96"));
}
