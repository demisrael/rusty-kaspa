//! Daemon mode -- long-running gRPC service. The service surface
//! is the `kaspawalletd` proto vendored at
//! `proto/kaspawalletd.proto`; the build script (`build.rs`)
//! emits both server and client stubs from that proto.
//!
//! Module split:
//! - `pb` -- re-exports the tonic-generated message + server +
//!   client types under a stable in-crate path.
//! - `error` -- daemon-side error type for startup + RPC handler
//!   failure surfaces.
//! - `kaspad` -- narrow trait + production wrapper around the
//!   kaspad gRPC RPC surface the daemon depends on.
//! - `state` -- mutex-guarded daemon state: address-set, UTXO
//!   snapshot, mempool-excluded outpoints, sync progress,
//!   keyfile-bound identity.
//! - `sync` -- background sync loop driver.
//! - `service` -- `KaspawalletdSvc` implementation of the gRPC
//!   service trait.
//! - `run` -- `start_daemon` CLI entry point and the
//!   `serve_with_listener` test helper that accepts an
//!   already-bound `TcpListener` for ephemeral-port integration
//!   tests.
//! - `client` -- `DaemonClient` dial helper wrapping the
//!   generated tonic client so client subcommands construct a
//!   connection by address string without re-deriving the tonic
//!   boilerplate per call-site.

pub mod client;
pub mod error;
pub mod kaspad;
pub mod keysfile_lock;
pub mod pb;
pub mod run;
pub mod service;
pub mod state;
pub mod sync;

#[cfg(test)]
mod tests;

pub use client::DaemonClient;
pub use error::DaemonError;
pub use kaspad::{GrpcKaspadFacade, KaspadFacade};
pub use run::{ServeOptions, ShutdownTrigger, serve_with_listener, start_daemon};
pub use service::KaspawalletdSvc;
pub use state::{DaemonState, KeyChain, SharedState, SyncProgress, WalletAddress, WalletAddressSet, WalletUtxo, shared};
pub use sync::SyncLoop;
