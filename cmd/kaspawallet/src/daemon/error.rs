//! Daemon-side error type. Covers startup failures
//! (listener bind, keyfile load) and RPC handler failures that the
//! service translates into `tonic::Status`. Operator-facing
//! messages are ASCII-only and ticket-free.

use std::io;
use std::net::AddrParseError;

use thiserror::Error;

use crate::keyfile::KeyfileError;
use crate::keysource::KeySourceError;

/// Errors raised by the daemon during startup or while handling an
/// RPC. The variants cluster around four concerns:
///
/// - listener / network plumbing (`Bind`, `InvalidListenAddr`),
/// - keyfile loading on the daemon side (`Keyfile`, `KeySource`),
/// - runtime / shutdown plumbing (`Runtime`, `Shutdown`).
#[derive(Debug, Error)]
pub enum DaemonError {
    /// The configured listen address could not be parsed into a
    /// `SocketAddr`. Operator passed `--listen <invalid>`.
    #[error("invalid listen address '{addr}': {source}")]
    InvalidListenAddr {
        addr: String,
        #[source]
        source: AddrParseError,
    },

    /// Binding the TCP listener failed. Most commonly because the
    /// port is already in use.
    #[error("failed to bind listener at '{addr}': {source}")]
    Bind {
        addr: String,
        #[source]
        source: io::Error,
    },

    /// The keyfile at the resolved path could not be loaded.
    #[error("failed to load keyfile: {0}")]
    Keyfile(#[from] KeyfileError),

    /// Resolving the keyfile path or constructing a key source from
    /// the loaded keyfile failed.
    #[error("failed to resolve key source: {0}")]
    KeySource(#[from] KeySourceError),

    /// A generic runtime error (tonic transport setup, tokio I/O
    /// outside the bind path, etc.).
    #[error("daemon runtime error: {0}")]
    Runtime(String),

    /// A kaspad RPC call returned an error. Wraps the upstream
    /// `kaspa_rpc_core::RpcError` text rather than the typed enum
    /// so the daemon's error surface stays narrow.
    #[error("kaspad RPC error: {0}")]
    Kaspad(String),
}
