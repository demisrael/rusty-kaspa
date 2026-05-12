//! Byte-deterministic UTXO selection primitive that drives every
//! send / sweep / create-unsigned-transaction path.
//!
//! `select_utxos` returns a deterministic selected-UTXO order, a
//! `total_received`, and a `change_sompi` for the same logical
//! input set. The daemon owns the pre-filter (spendability,
//! `from_addresses`, `used_outpoints`); this module receives a
//! pre-filtered, pre-sorted slice and runs the algorithm core.
//!
//! Load-bearing determinism rules: two break conditions, the
//! one-extra-input KIP-9 rule for change, and the iteration order.

use kaspa_consensus_core::config::params::Params;

use super::error::CoinSelectError;
use super::fee::{WalletConfig, estimate_fee};
use crate::transaction::Utxo;

/// Minimum change-output amount the selector targets to dodge
/// KIP-9 storage-mass discontinuities. With at least 10 KAS in
/// the change output, KIP-9 storage mass charged for change is
/// at most 1000 gram.
const SOMPI_PER_KASPA: u64 = 100_000_000;
const MIN_CHANGE_TARGET: u64 = SOMPI_PER_KASPA * 10;

/// Result of a [`select_utxos`] call.
#[derive(Clone, Debug)]
pub struct Selection {
    /// UTXOs selected for the next unsigned transaction, in
    /// iteration order. Pre-selected UTXOs come first, followed
    /// by the largest-amount-first ordering produced by the
    /// daemon's `utxos_sorted_by_amount` slice.
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

/// UTXO selection with optional pre-selected inputs.
///
/// Inputs:
///
/// - `cfg` -- wallet keyfile parameters used by the inner
///   `estimate_fee` call.
/// - `params` -- consensus params for mass calculation.
/// - `sorted_utxos` -- a UTXO slice descending by amount,
///   already filtered for spendability and source-address /
///   used-outpoint membership.
/// - `pre_selected` -- explicit pre-selected UTXOs. The
///   `bump_fee` flow uses this; normal `send` calls pass an
///   empty slice. Iterated FIRST and excluded from the
///   second-loop scan.
/// - `spend_amount`, `is_send_all`, `fee_rate`, `max_fee` --
///   selection knobs.
///
/// Algorithm summary:
///
/// 1. Build a pre-selected outpoint set.
/// 2. Loop through `pre_selected` first.
/// 3. If still more value needed, loop through `sorted_utxos`,
///    skipping outpoints already in the pre-selected set.
/// 4. Each iteration: append the UTXO, recompute `fee` via
///    `estimate_fee` against the running selection + the
///    projected recipient value, and check the two break
///    conditions:
///    - `total_value == total_spend` -- single-input case,
///      no change needed -> stop.
///    - `total_value >= total_spend + MIN_CHANGE_TARGET &&
///      len(selected) > 1` -- KIP-9 dust-margin met AND at
///      least 2 inputs are present (the second condition is the
///      "small-input dust patch" that keeps the wallet from
///      emitting a low-value change output) -> stop.
/// 5. After the loops, compute `total_spend` + `total_received`
///    per the `is_send_all` policy.
/// 6. If `total_value < total_spend`: return InsufficientFunds.
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
    // The pre-selected set is keyed by Outpoint =
    // (transaction_id, index); serialise to (Vec<u8>, u32) for
    // easy comparison.
    let pre_selected_keys: Vec<(Vec<u8>, u32)> = pre_selected
        .iter()
        .map(|u| (u.outpoint.transaction_id.as_ref().map(|t| t.bytes.clone()).unwrap_or_default(), u.outpoint.index))
        .collect();

    let mut selected: Vec<Utxo> = Vec::new();
    let mut total_value: u64 = 0;
    let mut fee: u64 = 0;

    // Per-utxo iteration closure. Returns `Ok(true)` to continue
    // the outer loop, `Ok(false)` to break it.
    let iteration = |utxo: &Utxo,
                     _avoid_preselected: bool,
                     selected: &mut Vec<Utxo>,
                     total_value: &mut u64,
                     fee: &mut u64|
     -> Result<bool, CoinSelectError> {
        // Daemon-level filters (`from_addresses`,
        // `is_utxo_spendable`, `used_outpoints`) are owned by the
        // caller (the daemon pre-filters the input slice). The
        // `avoid_preselected` second-loop skip is implemented at
        // the call site below so the closure stays free of a
        // borrow collision with `pre_selected_keys`.

        selected.push(utxo.clone());
        *total_value += utxo.utxo_entry.amount;

        let estimated_recipient_value = if is_send_all { *total_value } else { spend_amount };

        *fee = estimate_fee(cfg, params, selected, fee_rate, max_fee, estimated_recipient_value)?;

        let total_spend = spend_amount + *fee;
        // Two break cases:
        //   1. !is_send_all AND total_value == total_spend.
        //   2. !is_send_all AND
        //      total_value >= total_spend + MIN_CHANGE_TARGET
        //      AND selected.len() > 1.
        if !is_send_all && (*total_value == total_spend || (*total_value >= total_spend + MIN_CHANGE_TARGET && selected.len() > 1)) {
            return Ok(false);
        }

        Ok(true)
    };

    let mut should_continue = true;

    // Loop 1: pre-selected outpoints, tried first regardless of
    // whether they appear in `sorted_utxos`.
    for utxo in pre_selected {
        should_continue = iteration(utxo, false, &mut selected, &mut total_value, &mut fee)?;
        if !should_continue {
            break;
        }
    }

    // Loop 2: sorted-by-amount; skip any outpoint already covered
    // by loop 1.
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

    // Tail block: compute total_spend / total_received and the
    // change amount.
    let (total_spend, total_received) =
        if is_send_all { (total_value, total_value.saturating_sub(fee)) } else { (spend_amount + fee, spend_amount) };

    if total_value < total_spend {
        return Err(CoinSelectError::InsufficientFunds { required: total_spend, available: total_value });
    }

    Ok(Selection { selected, total_received, change_sompi: total_value - total_spend })
}
