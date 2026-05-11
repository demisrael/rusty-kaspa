//! Verbatim port of Go's `selectUTXOs` /
//! `selectUTXOsWithPreselected` -- the byte-deterministic UTXO
//! ordering primitive that drives every send / sweep /
//! create-unsigned-transaction path.
//!
//! Source: https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/create_unsigned_transaction.go#L150
//!
//! This is the cross-binary parity battlefield: the Rust port's
//! `select_utxos` MUST return the same selected-UTXO order, the
//! same `total_received`, and the same `change_sompi` as Go for the
//! same logical input set. Daemon-level filtering
//! (`fromAddresses`, `isUTXOSpendable`, `usedOutpoints`) is the
//! caller's responsibility -- this module receives a pre-filtered,
//! pre-sorted slice of UTXOs and runs the algorithm core. The
//! daemon (B4) owns the filter; the algorithm core is the same
//! across both layers.
//!
//! The two break conditions, the one-extra-input KIP-9 rule for
//! change, and the iteration order are the load-bearing
//! determinism rules. Read line-for-line against the Go source.

use kaspa_consensus_core::config::params::Params;

use super::error::CoinSelectError;
use super::fee::{WalletConfig, estimate_fee};
use crate::transaction::Utxo;

/// The minimal change amount that the Go reference's selector
/// targets to dodge KIP-9 storage-mass discontinuities. Source:
/// `cmd/kaspawallet/daemon/server/create_unsigned_transaction.go:23`
/// `const minChangeTarget = constants.SompiPerKaspa * 10`. With at
/// least 10 KAS in the change output, KIP-9 storage mass charged
/// for change is at most 1000 gram (Go reference comment lines
/// 17-22).
const SOMPI_PER_KASPA: u64 = 100_000_000;
const MIN_CHANGE_TARGET: u64 = SOMPI_PER_KASPA * 10;

/// Result of a [`select_utxos`] call. Mirrors Go's
/// `(selectedUTXOs []*libkaspawallet.UTXO, totalReceived uint64,
/// changeSompi uint64, err error)` four-tuple.
#[derive(Clone, Debug)]
pub struct Selection {
    /// UTXOs selected for the next unsigned transaction, in
    /// iteration order (Go: append-order onto the `selectedUTXOs`
    /// slice). Pre-selected UTXOs come first, followed by the
    /// largest-amount-first ordering produced by the daemon's
    /// `s.utxosSortedByAmount` slice.
    pub selected: Vec<Utxo>,

    /// What the recipient receives. For `is_send_all = false` this
    /// equals `spend_amount`; for `is_send_all = true` it equals
    /// `total_value - fee`.
    pub total_received: u64,

    /// Change amount to be paid back to the wallet. Zero when the
    /// selection consumed the inputs exactly or when
    /// `is_send_all = true`.
    pub change_sompi: u64,
}

/// Verbatim Path-A port of Go's `selectUTXOsWithPreselected`
/// (`create_unsigned_transaction.go:155-261`).
///
/// Inputs:
///
/// - `cfg` -- wallet keyfile parameters used by the inner
///   `estimate_fee` call (the daemon's `*server` carries these via
///   `s.keysFile.*` + `s.params.*`).
/// - `params` -- consensus params for mass calculation.
/// - `sorted_utxos` -- the daemon's `utxosSortedByAmount` slice
///   (descending by `UTXOEntry.Amount()`), already filtered for
///   spendability + `fromAddresses` + `usedOutpoints`. The caller
///   is the daemon (B4); this module does not own the filters.
/// - `pre_selected` -- explicit pre-selected UTXOs (Go's
///   `preSelectedUTXOs`). The daemon's `bumpFee` flow uses this;
///   normal `send` calls pass an empty slice. Iterated FIRST and
///   excluded from the second-loop scan.
/// - `spend_amount`, `is_send_all`, `fee_rate`, `max_fee` --
///   matches Go's parameter set.
///
/// Algorithm summary (line numbers refer to the Go source):
///
/// 1. Build a pre-selected outpoint set
///    (`preSelectedSet`, lines 158-161).
/// 2. Loop through `pre_selected` first with `avoidPreselected =
///    false` (lines 222-232).
/// 3. If still need more value, loop through `sorted_utxos` with
///    `avoidPreselected = true`, skipping outpoints already in
///    `preSelectedSet` (lines 234-245).
/// 4. Each iteration: append the UTXO, recompute `fee` via
///    `estimate_fee` against the running selection + the projected
///    recipient value, and check the two break conditions
///    (lines 215-217):
///    - `total_value == total_spend` -- single-input case,
///      no change needed -> stop.
///    - `total_value >= total_spend + MIN_CHANGE_TARGET &&
///      len(selected) > 1` -- KIP-9 dust-margin met AND we have
///      at least 2 inputs (Go comment lines 213-214: `go-nodes
///      dust patch we try and find at least 2 inputs even though
///      the next one is not necessary in terms of spend value`)
///      -> stop.
/// 5. After the loops, compute `total_spend` + `total_received` by
///    `is_send_all` policy (lines 247-254).
/// 6. If `total_value < total_spend`: return InsufficientFunds
///    (lines 255-258).
/// 7. Return `(selected, total_received, total_value - total_spend)`.
pub fn select_utxos(
    cfg: &WalletConfig,
    params: &Params,
    sorted_utxos: &[Utxo],
    pre_selected: &[Utxo],
    spend_amount: u64,
    is_send_all: bool,
    fee_rate: f64,
    max_fee: u64,
) -> Result<Selection, CoinSelectError> {
    // Mirror Go's preSelectedSet construction (lines 158-161).
    // The set is keyed by Outpoint = (transaction_id, index); we
    // serialise that to (Vec<u8>, u32) for easy comparison.
    let pre_selected_keys: Vec<(Vec<u8>, u32)> = pre_selected
        .iter()
        .map(|u| (u.outpoint.transaction_id.as_ref().map(|t| t.bytes.clone()).unwrap_or_default(), u.outpoint.index))
        .collect();

    let mut selected: Vec<Utxo> = Vec::new();
    let mut total_value: u64 = 0;
    let mut fee: u64 = 0;

    // Closure mirroring Go's anonymous `iteration` (lines 170-220).
    // Returns `Ok(true)` to continue the outer loop, `Ok(false)` to
    // break it.
    let iteration = |utxo: &Utxo,
                     _avoid_preselected: bool,
                     selected: &mut Vec<Utxo>,
                     total_value: &mut u64,
                     fee: &mut u64|
     -> Result<bool, CoinSelectError> {
        // Daemon-level filters (`fromAddresses` /
        // `isUTXOSpendable` / `usedOutpoints`) are owned by the
        // caller in this port (the daemon pre-filters the input
        // slice). The `avoid_preselected` second-loop skip is
        // implemented at the call site below so the closure stays
        // free of borrow-collision with `pre_selected_keys`.

        selected.push(utxo.clone());
        *total_value += utxo.utxo_entry.amount;

        let estimated_recipient_value = if is_send_all { *total_value } else { spend_amount };

        *fee = estimate_fee(cfg, params, selected, fee_rate, max_fee, estimated_recipient_value)?;

        let total_spend = spend_amount + *fee;
        // Two break cases (mirror Go comment block lines 210-214 +
        // condition line 215):
        //   1. !is_send_all AND total_value == total_spend
        //   2. !is_send_all AND total_value >= total_spend +
        //      MIN_CHANGE_TARGET AND selected.len() > 1
        if !is_send_all && (*total_value == total_spend || (*total_value >= total_spend + MIN_CHANGE_TARGET && selected.len() > 1)) {
            return Ok(false);
        }

        Ok(true)
    };

    let mut should_continue = true;

    // Loop 1: pre-selected (Go lines 222-232). avoidPreselected =
    // false here; pre-selected outpoints are tried first regardless
    // of whether they show up in `sorted_utxos`.
    for utxo in pre_selected {
        should_continue = iteration(utxo, false, &mut selected, &mut total_value, &mut fee)?;
        if !should_continue {
            break;
        }
    }

    // Loop 2: sorted-by-amount (Go lines 234-245). avoidPreselected
    // = true; skip any outpoint already covered by loop 1.
    if should_continue {
        for utxo in sorted_utxos {
            let outpoint_key =
                (utxo.outpoint.transaction_id.as_ref().map(|t| t.bytes.clone()).unwrap_or_default(), utxo.outpoint.index);
            if pre_selected_keys.contains(&outpoint_key) {
                continue;
            }

            let cont = iteration(utxo, true, &mut selected, &mut total_value, &mut fee)?;
            if !cont {
                break;
            }
        }
    }

    // Mirror Go's tail block (lines 247-260).
    let (total_spend, total_received) =
        if is_send_all { (total_value, total_value.saturating_sub(fee)) } else { (spend_amount + fee, spend_amount) };

    if total_value < total_spend {
        return Err(CoinSelectError::InsufficientFunds { required: total_spend, available: total_value });
    }

    Ok(Selection { selected, total_received, change_sompi: total_value - total_spend })
}
