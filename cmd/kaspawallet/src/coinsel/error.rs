//! Errors surfaced by the coin-selection / fee-estimation layer.

use thiserror::Error;

use crate::sign::SignError;
use crate::transaction::TransactionError;

/// Errors returned by [`super::select_utxos`] +
/// [`super::estimate_fee`]. Mirrors the Go reference's `errors.Errorf`
/// surface in `daemon/server/create_unsigned_transaction.go` (the
/// `selectUTXOsWithPreselected` and `estimateFee` paths) plus the
/// rustic addition of typed wrappers around the underlying
/// transaction-build / mass-calc errors.
#[derive(Debug, Error)]
pub enum CoinSelectError {
    /// Mirrors Go's
    /// `errors.Errorf("Insufficient funds for send: %f required, while only %f available", ...)`
    /// at `create_unsigned_transaction.go:256-258`. Sompi values
    /// (not the float Go formats) so callers can render whatever
    /// unit they prefer; the message body uses sompi too for
    /// debug clarity.
    #[error("insufficient funds: {required} sompi required, {available} sompi available")]
    InsufficientFunds { required: u64, available: u64 },

    /// Mirrors Go's
    /// `errors.Errorf("requested fee rate %f is too low, minimum fee rate is %f", ...)`
    /// at `calculateFeeLimits` (`create_unsigned_transaction.go:55,
    /// 63`). Callers that compute a fee rate floor outside this
    /// module (e.g. the daemon's policy layer) raise this directly.
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
