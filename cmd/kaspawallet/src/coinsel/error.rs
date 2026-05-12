//! Errors surfaced by the coin-selection / fee-estimation layer.

use thiserror::Error;

use crate::sign::SignError;
use crate::transaction::TransactionError;

/// Errors returned by [`super::select_utxos`] +
/// [`super::estimate_fee`]. Adds typed wrappers around the
/// underlying transaction-build / mass-calc errors.
#[derive(Debug, Error)]
pub enum CoinSelectError {
    /// Coin selection could not assemble enough value to cover the
    /// requested send. Values are in sompi.
    #[error("insufficient funds: {required} sompi required, {available} sompi available")]
    InsufficientFunds { required: u64, available: u64 },

    /// The fee rate requested by the caller is below the mempool's
    /// `MIN_FEE_RATE` floor.
    #[error("requested fee rate {requested} below minimum {minimum}")]
    FeeRateTooLow { requested: f64, minimum: f64 },

    /// Wrapper around the unsigned-PST builder's failure modes.
    /// Most call sites that hit this also hit a config-time error
    /// (bad xpub, bad address); fee estimation invokes
    /// `create_unsigned_transaction` internally so the wrapper is
    /// load-bearing.
    #[error(transparent)]
    Transaction(#[from] TransactionError),

    /// Wrapper around the mass calculator's failure modes. Mass
    /// estimation ([`crate::mass`]) lifts the PST into consensus
    /// types and may surface a structural error if the PST is
    /// internally inconsistent.
    #[error(transparent)]
    Mass(#[from] SignError),
}
