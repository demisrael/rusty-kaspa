//! Subcommand-style wallet binary mirroring the legacy Go `kaspawallet`.
//!
//! Crate scope: legacy Go-keyfile native read + multisig + CLI surface
//! parity with the Go `cmd/kaspawallet` binary. Full architectural
//! contract is documented in the task spec.

pub mod cli;
pub mod coinsel;
pub mod daemon;
pub mod dispatch;
pub mod keyfile;
pub mod keysource;
pub mod mass;
pub mod parse;
pub mod serialization;
pub mod sign;
pub mod transaction;
pub mod transactions_hex;
pub mod version;
