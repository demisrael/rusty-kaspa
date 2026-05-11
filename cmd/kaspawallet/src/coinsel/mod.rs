//! Verbatim Path-A port of the Go daemon's coin-selection layer
//! (`selectUTXOs` + `selectUTXOsWithPreselected` + `estimateFee` +
//! `estimateFeePerInput`). The byte-deterministic UTXO ordering
//! this module produces is the load-bearing property the
//! cross-binary `send` parity test and the side-by-side
//! `send` / `create-unsigned-transaction` / `sweep` parity matrix
//! depend on. Every iteration order, every fee arithmetic step,
//! and every break condition mirrors the Go reference exactly so
//! two callers (Go binary and Rust port) seeing the same logical
//! input produce byte-identical PSTs.
//!
//! Source: https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/create_unsigned_transaction.go
//!
//! Reuse-existing-crates discipline: the mass primitive
//! ([`crate::mass::estimate_mass_after_signatures`]) is the only
//! mass-formula owner; the unsigned-PST builder
//! ([`crate::transaction::create_unsigned_transaction`]) is the
//! only PST-shape owner. This module's responsibility is the
//! ordering rule, the fee arithmetic, and the change-amount
//! computation. No mass formula is re-derived here; no PST shape
//! is re-emitted here.

mod error;
mod fee;
mod select;
mod split;

#[cfg(test)]
mod tests;

pub use error::CoinSelectError;
pub use fee::{WalletConfig, estimate_fee, estimate_fee_per_input};
pub use select::{Selection, select_utxos};
pub use split::{MAXIMUM_STANDARD_TRANSACTION_MASS, maybe_auto_compound_transaction, maybe_split_and_merge_transaction};
