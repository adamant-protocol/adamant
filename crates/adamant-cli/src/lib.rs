//! Adamant operator CLI library.
//!
//! Phase 9.1 deliverable — the offline operator CLI for
//! validator-key generation + `ValidatorId` derivation +
//! version reporting. The library surface is testable; the
//! `adamant-cli` binary wraps it as the entry point.
//!
//! # Phase 9.1 scope
//!
//! Intentionally minimal — networking RPC subcommands (status
//! queries, transaction submission) wait for Phase 9.2 when
//! the node RPC surface lands. The Phase 9.1 surface is
//! standalone-offline:
//!
//! - [`Command::Version`] — print Adamant protocol version +
//!   network protocol version.
//! - [`Command::KeysGenerateBls`] — generate a fresh BLS12-381
//!   keypair (for validator BLS-signing keys). Output:
//!   secret + public hex blobs.
//! - [`Command::KeysDeriveValidatorId`] — given an (Ed25519,
//!   ML-DSA, BLS) public-key bundle in hex, derive the §8.1.2
//!   `ValidatorId`.
//!
//! Operator key management for production validators (HSM /
//! KMS / on-disk-encrypted storage) is operational work
//! belonging to deployment tooling, not the CLI primitive.
//!
//! # Honest framing
//!
//! Phase 9.1 ships an offline-tools CLI. It does NOT yet:
//! - Connect to a running node.
//! - Submit transactions.
//! - Query chain state.
//! - Generate Ed25519 or ML-DSA keys (the BLS-only output is
//!   sufficient for the §8.1 validator role; the full bundle
//!   needs §3.4 `ed25519-dalek` + `ml_dsa` wiring which lands at
//!   Phase 9.2).

#![forbid(unsafe_code)]

use adamant_consensus::{
    ValidatorId, ValidatorPublicKeys, BLS_PUBLIC_KEY_BYTES, ED25519_PUBLIC_KEY_BYTES,
    ML_DSA_PUBLIC_KEY_BYTES,
};
use adamant_crypto::bls;

/// CLI command dispatch. Parsed from `std::env::args` by the
/// binary entry point; consumed by [`execute`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Command {
    /// Print protocol version + crate-version metadata.
    Version,

    /// Generate a fresh BLS12-381 keypair using the supplied
    /// initial-key-material seed. The IKM seed MUST be at
    /// least 32 bytes; production callers should source it
    /// from a CSPRNG (e.g., `OsRng`) rather than user input.
    KeysGenerateBls {
        /// 32-byte IKM seed (hex-decoded by the binary
        /// entry point from operator input).
        ikm: Vec<u8>,
    },

    /// Derive the §8.1.2 `ValidatorId` from a public-key
    /// bundle in hex. Each component is hex-encoded; total
    /// canonical bundle size is 32 (Ed25519) + 1952 (ML-DSA-65)
    /// + 96 (BLS) = 2,080 bytes.
    KeysDeriveValidatorId {
        /// Hex-encoded Ed25519 public key (32 bytes).
        ed25519_hex: String,
        /// Hex-encoded ML-DSA-65 public key (1952 bytes).
        ml_dsa_hex: String,
        /// Hex-encoded BLS12-381 G1 compressed public key
        /// (96 bytes).
        bls_hex: String,
    },
}

/// Output produced by [`execute`]. Human-readable text;
/// the binary entry point writes it to stdout.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    /// The output text the binary writes to stdout.
    pub stdout: String,
}

/// Typed errors produced by [`execute`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CliError {
    /// The IKM seed for [`Command::KeysGenerateBls`] was
    /// rejected by the BLS keygen primitive (too short, or
    /// the resulting scalar was zero — astronomically rare).
    BlsKeygenFailed(String),

    /// A hex-decoded public-key component had the wrong
    /// byte width.
    PublicKeyWidthMismatch {
        /// The component that had the wrong width
        /// (`"ed25519"`, `"ml_dsa"`, or `"bls"`).
        component: &'static str,
        /// The width actually supplied.
        actual: usize,
        /// The width expected.
        expected: usize,
    },

    /// A hex-encoded public-key component failed to decode.
    HexDecodeFailed {
        /// The component that failed to decode.
        component: &'static str,
        /// Underlying hex-crate error message.
        reason: String,
    },
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::BlsKeygenFailed(s) => write!(f, "BLS keygen failed: {s}"),
            Self::PublicKeyWidthMismatch {
                component,
                actual,
                expected,
            } => write!(
                f,
                "{component} public key width mismatch: got {actual} bytes, need {expected}"
            ),
            Self::HexDecodeFailed { component, reason } => {
                write!(f, "{component} hex decode failed: {reason}")
            }
        }
    }
}

impl std::error::Error for CliError {}

/// Execute a parsed [`Command`] and produce the
/// [`CommandOutput`] for stdout.
///
/// # Errors
///
/// Returns [`CliError`] for each subcommand-specific failure
/// path.
pub fn execute(cmd: &Command) -> Result<CommandOutput, CliError> {
    match cmd {
        Command::Version => Ok(CommandOutput {
            stdout: format!(
                "adamant-cli {}\nadamant-consensus crate version: {}\n",
                env!("CARGO_PKG_VERSION"),
                "0.0.1" // workspace-pinned
            ),
        }),
        Command::KeysGenerateBls { ikm } => {
            let sk = bls::SecretKey::from_ikm(ikm)
                .map_err(|e| CliError::BlsKeygenFailed(format!("{e:?}")))?;
            let pk = sk.public_key();
            Ok(CommandOutput {
                stdout: format!(
                    "BLS keypair generated.\nsecret_hex: {}\npublic_hex: {}\n",
                    hex::encode(sk.to_bytes()),
                    hex::encode(pk.to_bytes())
                ),
            })
        }
        Command::KeysDeriveValidatorId {
            ed25519_hex,
            ml_dsa_hex,
            bls_hex,
        } => {
            let ed25519_bytes =
                hex::decode(ed25519_hex).map_err(|e| CliError::HexDecodeFailed {
                    component: "ed25519",
                    reason: e.to_string(),
                })?;
            let ml_dsa_bytes = hex::decode(ml_dsa_hex).map_err(|e| CliError::HexDecodeFailed {
                component: "ml_dsa",
                reason: e.to_string(),
            })?;
            let bls_bytes = hex::decode(bls_hex).map_err(|e| CliError::HexDecodeFailed {
                component: "bls",
                reason: e.to_string(),
            })?;
            if ed25519_bytes.len() != ED25519_PUBLIC_KEY_BYTES {
                return Err(CliError::PublicKeyWidthMismatch {
                    component: "ed25519",
                    actual: ed25519_bytes.len(),
                    expected: ED25519_PUBLIC_KEY_BYTES,
                });
            }
            if ml_dsa_bytes.len() != ML_DSA_PUBLIC_KEY_BYTES {
                return Err(CliError::PublicKeyWidthMismatch {
                    component: "ml_dsa",
                    actual: ml_dsa_bytes.len(),
                    expected: ML_DSA_PUBLIC_KEY_BYTES,
                });
            }
            if bls_bytes.len() != BLS_PUBLIC_KEY_BYTES {
                return Err(CliError::PublicKeyWidthMismatch {
                    component: "bls",
                    actual: bls_bytes.len(),
                    expected: BLS_PUBLIC_KEY_BYTES,
                });
            }
            let mut ed25519 = [0u8; ED25519_PUBLIC_KEY_BYTES];
            ed25519.copy_from_slice(&ed25519_bytes);
            let mut ml_dsa = [0u8; ML_DSA_PUBLIC_KEY_BYTES];
            ml_dsa.copy_from_slice(&ml_dsa_bytes);
            let mut bls = [0u8; BLS_PUBLIC_KEY_BYTES];
            bls.copy_from_slice(&bls_bytes);
            let pubkeys = ValidatorPublicKeys::new(ed25519, ml_dsa, bls);
            let validator_id: ValidatorId = pubkeys.derive_id();
            Ok(CommandOutput {
                stdout: format!("validator_id: {}\n", hex::encode(validator_id.as_bytes())),
            })
        }
    }
}

/// Parse `args` (typically `std::env::args().skip(1).collect()`)
/// into a [`Command`]. Returns `None` for unrecognised inputs
/// (the binary entry point handles the help message + exit).
#[must_use]
pub fn parse_args(args: &[String]) -> Option<Command> {
    match args.first().map(String::as_str) {
        Some("version" | "--version" | "-v") => Some(Command::Version),
        Some("keys") => match args.get(1).map(String::as_str) {
            Some("generate-bls") => {
                let ikm_hex = args.get(2)?;
                let ikm = hex::decode(ikm_hex).ok()?;
                Some(Command::KeysGenerateBls { ikm })
            }
            Some("derive-validator-id") => Some(Command::KeysDeriveValidatorId {
                ed25519_hex: args.get(2)?.clone(),
                ml_dsa_hex: args.get(3)?.clone(),
                bls_hex: args.get(4)?.clone(),
            }),
            _ => None,
        },
        _ => None,
    }
}

/// Help text printed when [`parse_args`] returns `None`.
pub const HELP_TEXT: &str = "\
adamant-cli — Adamant operator command-line tool

USAGE:
    adamant-cli <COMMAND>

COMMANDS:
    version
        Print protocol + crate version metadata.

    keys generate-bls <IKM_HEX>
        Generate a fresh BLS12-381 validator-signing keypair.
        IKM_HEX is the hex-encoded 32+-byte initial-key-material
        seed; production callers MUST source this from a CSPRNG.

    keys derive-validator-id <ED25519_HEX> <ML_DSA_HEX> <BLS_HEX>
        Compute the §8.1.2 ValidatorId from a public-key
        bundle. Each component is hex-encoded; widths must
        match the §3.4 spec (32 / 1952 / 96 bytes).

PHASE 9.1 SCOPE:
    Offline operator tools only. Networking RPC subcommands
    (status queries, transaction submission) land at Phase 9.2
    when the node RPC surface is wired through.
";

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_command_produces_output() {
        let out = execute(&Command::Version).expect("ok");
        assert!(out.stdout.contains("adamant-cli"));
        assert!(out.stdout.contains("adamant-consensus"));
    }

    #[test]
    fn keys_generate_bls_round_trip() {
        let ikm = vec![7u8; 32];
        let out = execute(&Command::KeysGenerateBls { ikm: ikm.clone() }).expect("ok");
        assert!(out.stdout.contains("BLS keypair generated."));
        assert!(out.stdout.contains("secret_hex:"));
        assert!(out.stdout.contains("public_hex:"));
        // Determinism: same IKM → same output.
        let out2 = execute(&Command::KeysGenerateBls { ikm }).expect("ok");
        assert_eq!(out, out2);
    }

    #[test]
    fn keys_generate_bls_short_ikm_errors() {
        // IKM too short — bls::SecretKey::from_ikm rejects
        // inputs shorter than 32 bytes.
        let out = execute(&Command::KeysGenerateBls { ikm: vec![1u8; 10] });
        assert!(matches!(out, Err(CliError::BlsKeygenFailed(_))));
    }

    #[test]
    fn keys_derive_validator_id_canonical() {
        // Construct a fixture bundle (all-1s components) and
        // verify the CLI produces the same ValidatorId as
        // the direct ValidatorPublicKeys::derive_id() call.
        let pubkeys = ValidatorPublicKeys::new(
            [1u8; ED25519_PUBLIC_KEY_BYTES],
            [1u8; ML_DSA_PUBLIC_KEY_BYTES],
            [1u8; BLS_PUBLIC_KEY_BYTES],
        );
        let expected = pubkeys.derive_id();
        let cmd = Command::KeysDeriveValidatorId {
            ed25519_hex: hex::encode([1u8; ED25519_PUBLIC_KEY_BYTES]),
            ml_dsa_hex: hex::encode([1u8; ML_DSA_PUBLIC_KEY_BYTES]),
            bls_hex: hex::encode([1u8; BLS_PUBLIC_KEY_BYTES]),
        };
        let out = execute(&cmd).expect("ok");
        let expected_hex = hex::encode(expected.as_bytes());
        assert!(
            out.stdout.contains(&expected_hex),
            "stdout {} should contain {}",
            out.stdout,
            expected_hex
        );
    }

    #[test]
    fn keys_derive_validator_id_rejects_wrong_width() {
        let cmd = Command::KeysDeriveValidatorId {
            ed25519_hex: hex::encode([1u8; 16]), // wrong: 16 not 32
            ml_dsa_hex: hex::encode([1u8; ML_DSA_PUBLIC_KEY_BYTES]),
            bls_hex: hex::encode([1u8; BLS_PUBLIC_KEY_BYTES]),
        };
        let err = execute(&cmd).expect_err("must reject");
        match err {
            CliError::PublicKeyWidthMismatch {
                component, actual, ..
            } => {
                assert_eq!(component, "ed25519");
                assert_eq!(actual, 16);
            }
            other => panic!("expected width mismatch, got {other:?}"),
        }
    }

    #[test]
    fn keys_derive_validator_id_rejects_bad_hex() {
        let cmd = Command::KeysDeriveValidatorId {
            ed25519_hex: "not-valid-hex".to_string(),
            ml_dsa_hex: hex::encode([1u8; ML_DSA_PUBLIC_KEY_BYTES]),
            bls_hex: hex::encode([1u8; BLS_PUBLIC_KEY_BYTES]),
        };
        let err = execute(&cmd).expect_err("must reject");
        assert!(matches!(err, CliError::HexDecodeFailed { .. }));
    }

    #[test]
    fn parse_args_version() {
        assert_eq!(parse_args(&["version".into()]), Some(Command::Version));
        assert_eq!(parse_args(&["--version".into()]), Some(Command::Version));
        assert_eq!(parse_args(&["-v".into()]), Some(Command::Version));
    }

    #[test]
    fn parse_args_keys_generate_bls() {
        let parsed = parse_args(&["keys".into(), "generate-bls".into(), hex::encode([7u8; 32])]);
        match parsed {
            Some(Command::KeysGenerateBls { ikm }) => assert_eq!(ikm.len(), 32),
            other => panic!("expected KeysGenerateBls, got {other:?}"),
        }
    }

    #[test]
    fn parse_args_unknown_returns_none() {
        assert!(parse_args(&[]).is_none());
        assert!(parse_args(&["unknown".into()]).is_none());
        assert!(parse_args(&["keys".into(), "unknown".into()]).is_none());
    }

    #[test]
    fn help_text_mentions_all_commands() {
        assert!(HELP_TEXT.contains("version"));
        assert!(HELP_TEXT.contains("keys generate-bls"));
        assert!(HELP_TEXT.contains("keys derive-validator-id"));
    }

    #[test]
    fn cli_error_implements_std_error() {
        fn assert_err<E: std::error::Error>() {}
        assert_err::<CliError>();
    }
}
