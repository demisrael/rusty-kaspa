//! Coin-selection layer (UTXO selection, fee estimation, and
//! mass-bound batch splitting). The byte-deterministic UTXO
//! ordering this module produces is the load-bearing property the
//! cross-implementation parity tests depend on.
//!
//! The mass primitive
//! ([`crate::mass::estimate_mass_after_signatures`]) is the only
//! mass-formula owner; the unsigned-PST builder
//! ([`crate::transaction::create_unsigned_transaction`]) is the
//! only PST-shape owner. This module's responsibility is the
//! ordering rule, the fee arithmetic, and the change-amount
//! computation -- no mass formula is re-derived here; no PST
//! shape is re-emitted here.

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
