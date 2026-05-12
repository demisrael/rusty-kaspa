//! Errors raised by the key-source layer.

use thiserror::Error;

use crate::keyfile::KeyfileError;

/// Error returned by the wallet-backend resolver. The error
/// wording follows the spec contract for the `--wallet-backend`
/// reserved-value path: ticket-free, structured, and
/// operator-facing.
#[derive(Debug, Error)]
pub enum ResolveError {
    #[error("wallet backend '{backend}' is not available in this build")]
    BackendNotAvailable { backend: &'static str },
    #[error("{0}")]
    KeySource(#[from] KeySourceError),
}

#[derive(Debug, Error)]
pub enum KeySourceError {
    #[error("keyfile error: {0}")]
    Keyfile(#[from] KeyfileError),
    #[error("bip32 derivation error: {0}")]
    Bip32(#[from] kaspa_bip32::Error),
    #[error("invalid keyfile field {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("redeem-script construction failed: {0}")]
    RedeemScript(String),
    /// Neither `--keys-file` nor the platform-aware default
    /// path resolves to an existing keyfile on disk.
    #[error("keyfile not found at default path '{default}' or any operator-supplied override")]
    DefaultPathMissing { default: String },
    /// The platform-aware default-path resolver could not
    /// determine an application data directory (no `$HOME`,
    /// no `%LOCALAPPDATA%`).
    #[error("could not determine default key-path: no application data directory available on this platform")]
    NoAppDataDir,
}
