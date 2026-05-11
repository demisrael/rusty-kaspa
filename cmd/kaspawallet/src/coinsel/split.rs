//! Verbatim Path-A port of the Go daemon's mass-bound transaction
//! splitter and the recursive merge-transaction chain.
//!
//! Source: https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/split_transaction.go
//!
//! When an unsigned transaction's compute-mass exceeds the kaspad
//! mempool's `MaximumStandardTransactionMass` ceiling (100 000
//! grams), the Go daemon splits the inputs into N batches, each
//! with its own change output paying back to the wallet, and then
//! emits a separate merge transaction that consumes the splits'
//! outputs to pay the original recipient. This module preserves
//! that algorithm line-for-line so the daemon's
//! `CreateUnsignedTransactions` RPC return path emits byte-identical
//! `[][]byte` slices versus the Go binary on the same input set.
//!
//! Daemon-state dependencies (`s.utxosSortedByAmount` for
//! `more_utxos_for_merge_transaction`) are caller-owned; the
//! caller passes the post-filter sorted UTXO pool (minus
//! anything already consumed by the original transaction's
//! coin-selection step) as `spare_utxos`. The B4 daemon will
//! own the filter step; this module owns the algorithm.

use kaspa_addresses::Address;
use kaspa_consensus_core::config::params::Params;
use kaspa_consensus_core::tx::{ScriptPublicKey, UtxoEntry};

use super::error::CoinSelectError;
use super::fee::{WalletConfig, estimate_fee, estimate_fee_per_input};
use crate::mass::estimate_compute_mass_after_signatures;
use crate::serialization::{serialize_partially_signed_transaction, wire};
use crate::transaction::{Payment, Utxo, create_unsigned_transaction, outpoint};

/// Maximum compute-mass a standard transaction may carry on the
/// kaspa mempool's `check_transaction_standard` path. Mirrors Go's
/// `mempool.MaximumStandardTransactionMass = 100_000`
/// (`domain/miningmanager/mempool/check_transaction_standard.go:41`)
/// and rusty-kaspa's `wallet/core/src/tx/mass.rs:24`. Pinned here
/// so the splitter does not depend on either crate just to read
/// one protocol constant.
pub const MAXIMUM_STANDARD_TRANSACTION_MASS: u64 = 100_000;

/// Minimum fee rate (sompi per gram) the Go reference accepts on
/// any tx the wallet daemon emits. Mirrors Go's
/// `minFeeRate = 1.0` at
/// `cmd/kaspawallet/daemon/server/create_unsigned_transaction.go:26`.
const MIN_FEE_RATE: f64 = 1.0;

/// The DAA-score the Go reference uses for synthetic UTXOs the
/// merge-transaction step builds from each split-transaction's
/// first output. Mirrors `constants.UnacceptedDAAScore`
/// (`domain/consensus/utils/constants/constants.go`); the value is
/// not load-bearing for byte-identity (the synthetic UTXO never
/// hits the wire), but the port preserves it so the synthetic
/// shape matches Go's stored shape on the daemon side.
const UNACCEPTED_DAA_SCORE: u64 = u64::MAX;

/// Verbatim port of Go's `maybeAutoCompoundTransaction`
/// (`split_transaction.go:24-39`). Returns the serialized
/// `PartiallySignedTransaction` bytes for each split + merge
/// transaction the splitter emitted, in the same order Go does.
///
/// `transaction` is the original unsigned PST returned by the
/// coin-selection layer. `to_address` / `change_address` /
/// `change_derivation_path` describe the merge transaction's
/// destination + change-back rules (the daemon's
/// `walletAddressPath(changeWalletAddress)` lookup is replaced
/// with a caller-supplied string so this module stays daemon-state
/// free). `spare_utxos` is the post-filter sorted-desc UTXO pool
/// minus anything already consumed by `transaction`; the
/// merge-transaction's `more_utxos_for_merge_transaction` step
/// scans it when the splits do not produce enough value to cover
/// the original recipient amount.
pub fn maybe_auto_compound_transaction(
    cfg: &WalletConfig,
    params: &Params,
    transaction: wire::PartiallySignedTransaction,
    to_address: &Address,
    change_address: &Address,
    change_derivation_path: &str,
    fee_rate: f64,
    max_fee: u64,
    spare_utxos: &[Utxo],
) -> Result<Vec<Vec<u8>>, CoinSelectError> {
    let split_transactions = maybe_split_and_merge_transaction(
        cfg,
        params,
        transaction,
        to_address,
        change_address,
        change_derivation_path,
        fee_rate,
        max_fee,
        spare_utxos,
    )?;

    let mut bytes_out: Vec<Vec<u8>> = Vec::with_capacity(split_transactions.len());
    for pst in &split_transactions {
        bytes_out.push(serialize_partially_signed_transaction(pst).map_err(|e| {
            CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
                reason: format!("serialize split: {e}"),
            })
        })?);
    }
    Ok(bytes_out)
}

/// Verbatim port of Go's `maybeSplitAndMergeTransaction`
/// (`split_transaction.go:143-196`). Recursive: when the splitter
/// produces N > 1 splits, the merge transaction is itself fed
/// back into this function so a still-too-big merge is split
/// further. The Go reference's comment notes recursion depth is
/// 2-3 in the rarest cases.
pub fn maybe_split_and_merge_transaction(
    cfg: &WalletConfig,
    params: &Params,
    transaction: wire::PartiallySignedTransaction,
    to_address: &Address,
    change_address: &Address,
    change_derivation_path: &str,
    fee_rate: f64,
    max_fee: u64,
    spare_utxos: &[Utxo],
) -> Result<Vec<wire::PartiallySignedTransaction>, CoinSelectError> {
    check_transaction_fee_rate(params, &transaction, max_fee, cfg.ecdsa)?;

    let transaction_mass = estimate_compute_mass_after_signatures(&transaction, params, cfg.ecdsa)?;
    if transaction_mass < MAXIMUM_STANDARD_TRANSACTION_MASS {
        return Ok(vec![transaction]);
    }

    let (split_count, inputs_per_split_count) =
        split_and_input_per_split_counts(cfg, params, &transaction, transaction_mass, change_address, fee_rate, max_fee)?;

    let mut splits: Vec<wire::PartiallySignedTransaction> = Vec::with_capacity(split_count);
    for i in 0..split_count {
        let start_index = i * inputs_per_split_count;
        let end_index = start_index + inputs_per_split_count;
        let split = create_split_transaction(cfg, params, &transaction, change_address, start_index, end_index, fee_rate, max_fee)?;
        check_transaction_fee_rate(params, &split, max_fee, cfg.ecdsa)?;
        splits.push(split);
    }

    if splits.len() > 1 {
        let merge = merge_transaction(
            cfg,
            params,
            &splits,
            &transaction,
            to_address,
            change_address,
            change_derivation_path,
            fee_rate,
            max_fee,
            spare_utxos,
        )?;
        // Mirror Go's recursion (split_transaction.go:187-191).
        let split_merge = maybe_split_and_merge_transaction(
            cfg,
            params,
            merge,
            to_address,
            change_address,
            change_derivation_path,
            fee_rate,
            max_fee,
            spare_utxos,
        )?;
        splits.extend(split_merge);
    }

    Ok(splits)
}

/// Verbatim port of Go's `transactionFeeRate`
/// (`split_transaction.go:108-128`). Returns `(total_in - total_out)
/// / compute_mass`. Errors when the transaction underpays its
/// outputs (`InsufficientFunds`-style mismatch).
fn transaction_fee_rate(params: &Params, ps_tx: &wire::PartiallySignedTransaction, ecdsa: bool) -> Result<f64, CoinSelectError> {
    let total_outs: u64 = ps_tx.tx.as_ref().map(|tx| tx.outputs.iter().map(|o| o.value).sum()).unwrap_or(0);
    let total_ins: u64 = ps_tx.partially_signed_inputs.iter().filter_map(|psi| psi.prev_output.as_ref().map(|po| po.value)).sum();

    if total_ins < total_outs {
        return Err(CoinSelectError::InsufficientFunds { required: total_outs, available: total_ins });
    }
    let fee = total_ins - total_outs;
    let mass = estimate_compute_mass_after_signatures(ps_tx, params, ecdsa)?;
    if mass == 0 {
        // Mirror Go's div-by-zero behaviour: the function does not
        // guard, but compute_mass is positive for any non-empty tx
        // so the branch is defensive only.
        return Ok(0.0);
    }
    Ok(fee as f64 / mass as f64)
}

/// Verbatim port of Go's `checkTransactionFeeRate`
/// (`split_transaction.go:130-141`). Gates the fee_rate against
/// the `MIN_FEE_RATE` floor; raises a typed error so the caller
/// can surface the `max_fee` parameter that produced the
/// below-floor rate.
fn check_transaction_fee_rate(
    params: &Params,
    ps_tx: &wire::PartiallySignedTransaction,
    max_fee: u64,
    ecdsa: bool,
) -> Result<(), CoinSelectError> {
    let fee_rate = transaction_fee_rate(params, ps_tx, ecdsa)?;
    if fee_rate < MIN_FEE_RATE {
        return Err(CoinSelectError::FeeRateTooLow { requested: fee_rate, minimum: MIN_FEE_RATE });
    }
    let _ = max_fee; // mirror Go's signature; max_fee is informational here
    Ok(())
}

/// Verbatim port of Go's `splitAndInputPerSplitCounts`
/// (`split_transaction.go:198-235`). Returns
/// `(split_count, inputs_per_split_count)` for the
/// mass-bound batching.
fn split_and_input_per_split_counts(
    cfg: &WalletConfig,
    params: &Params,
    transaction: &wire::PartiallySignedTransaction,
    transaction_mass: u64,
    change_address: &Address,
    fee_rate: f64,
    max_fee: u64,
) -> Result<(usize, usize), CoinSelectError> {
    // Step 1 (Go lines 202-208): clone tx with no inputs, calc its
    // mass, derive `mass_of_all_inputs = transaction_mass -
    // mass_without_inputs`.
    let tx_msg =
        transaction.tx.as_ref().ok_or(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
            reason: "transaction.tx missing".to_string(),
        }))?;
    let tx_without_inputs = wire::PartiallySignedTransaction {
        tx: Some(wire::TransactionMessage { inputs: Vec::new(), ..tx_msg.clone() }),
        partially_signed_inputs: Vec::new(),
    };
    let mass_without_inputs = estimate_compute_mass_after_signatures(&tx_without_inputs, params, cfg.ecdsa)?;
    let mass_of_all_inputs = transaction_mass.saturating_sub(mass_without_inputs);

    // Step 2 (Go lines 211-216): mass per input. Round up if
    // `mass_of_all_inputs % input_count > 0`.
    let input_count = tx_msg.inputs.len();
    if input_count == 0 {
        // Defensive: a zero-input tx cannot be split; return (1, 0)
        // so the outer loop emits a single split (which equals the
        // input tx) and exits. Go's reference assumes this branch
        // is unreachable from `maybeSplitAndMergeTransaction`'s
        // mass-gate; we preserve the assumption.
        return Ok((1, 0));
    }
    let mut mass_per_input = mass_of_all_inputs / input_count as u64;
    if mass_of_all_inputs % input_count as u64 > 0 {
        mass_per_input += 1;
    }
    if mass_per_input == 0 {
        // Defensive: zero per-input mass would divide-by-zero
        // below. Go's reference does not guard but the path
        // requires a non-zero mass to make progress.
        mass_per_input = 1;
    }

    // Step 3 (Go lines 219-226): create a dummy split with 0
    // inputs to measure the per-split overhead.
    let split_without_inputs = create_split_transaction(cfg, params, transaction, change_address, 0, 0, fee_rate, max_fee)?;
    let mass_for_everything_except_inputs_in_split =
        crate::mass::estimate_compute_mass_after_signatures(&split_without_inputs, params, cfg.ecdsa)?;
    let mass_for_inputs_in_split = MAXIMUM_STANDARD_TRANSACTION_MASS.saturating_sub(mass_for_everything_except_inputs_in_split);

    // Step 4 (Go lines 228-232): inputs per split + split count.
    let inputs_per_split_count = (mass_for_inputs_in_split / mass_per_input) as usize;
    if inputs_per_split_count == 0 {
        // Defensive guard; mirror Go's lack of a check by returning
        // an error if the policy cannot fit even one input per split.
        return Err(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
            reason: "per-input mass exceeds maximum standard transaction mass; cannot split".to_string(),
        }));
    }
    let mut split_count = input_count / inputs_per_split_count;
    if input_count % inputs_per_split_count > 0 {
        split_count += 1;
    }

    Ok((split_count, inputs_per_split_count))
}

/// Verbatim port of Go's `createSplitTransaction`
/// (`split_transaction.go:237-270`). Builds a single-output
/// (change-back) PST consuming a contiguous slice of the original
/// transaction's `partially_signed_inputs` from `start_index`
/// through `end_index` (exclusive).
fn create_split_transaction(
    cfg: &WalletConfig,
    params: &Params,
    transaction: &wire::PartiallySignedTransaction,
    change_address: &Address,
    start_index: usize,
    end_index: usize,
    fee_rate: f64,
    max_fee: u64,
) -> Result<wire::PartiallySignedTransaction, CoinSelectError> {
    let tx_msg =
        transaction.tx.as_ref().ok_or(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
            reason: "transaction.tx missing".to_string(),
        }))?;

    let mut selected_utxos: Vec<Utxo> = Vec::new();
    let mut total_sompi: u64 = 0;
    for i in start_index..end_index.min(transaction.partially_signed_inputs.len()) {
        let psi = &transaction.partially_signed_inputs[i];
        let prev =
            psi.prev_output.as_ref().ok_or(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
                reason: format!("psi[{i}].prev_output missing"),
            }))?;
        let spk_msg = prev.script_public_key.as_ref().ok_or(CoinSelectError::Transaction(
            crate::transaction::TransactionError::InvalidAddress { reason: format!("psi[{i}].prev_output.script_public_key missing") },
        ))?;
        let spk_version = u16::try_from(spk_msg.version).map_err(|_| {
            CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
                reason: format!("psi[{i}].prev_output.script_public_key.version exceeds u16"),
            })
        })?;
        let spk = ScriptPublicKey::new(spk_version, spk_msg.script.clone().into());

        let outpoint_msg = tx_msg.inputs.get(i).and_then(|inp| inp.previous_outpoint.clone()).ok_or(CoinSelectError::Transaction(
            crate::transaction::TransactionError::InvalidAddress { reason: format!("tx.inputs[{i}].previous_outpoint missing") },
        ))?;

        selected_utxos.push(Utxo {
            outpoint: outpoint_msg,
            utxo_entry: UtxoEntry {
                amount: prev.value,
                script_public_key: spk,
                block_daa_score: UNACCEPTED_DAA_SCORE,
                is_coinbase: false,
            },
            derivation_path: psi.derivation_path.clone(),
        });
        total_sompi += prev.value;
    }

    if !selected_utxos.is_empty() {
        let fee = estimate_fee(cfg, params, &selected_utxos, fee_rate, max_fee, total_sompi)?;
        total_sompi = total_sompi.saturating_sub(fee);
    }

    let payment = Payment { address: change_address.clone(), amount: total_sompi };
    Ok(create_unsigned_transaction(&cfg.extended_public_keys, cfg.minimum_signatures, &[payment], &selected_utxos)?)
}

/// Verbatim port of Go's `mergeTransaction`
/// (`split_transaction.go:41-106`). Builds the outer merge
/// transaction whose inputs are the split transactions' first
/// outputs and whose payee is the original recipient.
#[allow(clippy::too_many_arguments)] // mirror Go's parameter set; collapsing into a struct hurts call-site clarity
fn merge_transaction(
    cfg: &WalletConfig,
    params: &Params,
    split_transactions: &[wire::PartiallySignedTransaction],
    original_transaction: &wire::PartiallySignedTransaction,
    to_address: &Address,
    change_address: &Address,
    change_derivation_path: &str,
    fee_rate: f64,
    max_fee: u64,
    spare_utxos: &[Utxo],
) -> Result<wire::PartiallySignedTransaction, CoinSelectError> {
    let original_tx = original_transaction.tx.as_ref().ok_or(CoinSelectError::Transaction(
        crate::transaction::TransactionError::InvalidAddress { reason: "original_transaction.tx missing".to_string() },
    ))?;
    let num_outputs = original_tx.outputs.len();
    if num_outputs == 0 || num_outputs > 2 {
        // Mirror Go's sanity check (lines 51-58).
        return Err(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
            reason: format!("original transaction has {num_outputs} outputs, while 1 or 2 are expected"),
        }));
    }

    let sent_value = original_tx.outputs[0].value;
    let mut total_value: u64 = 0;
    let mut utxos: Vec<Utxo> = Vec::with_capacity(split_transactions.len());
    for split in split_transactions {
        let split_tx =
            split.tx.as_ref().ok_or(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
                reason: "split.tx missing".to_string(),
            }))?;
        if split_tx.outputs.is_empty() {
            return Err(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
                reason: "split.tx.outputs empty".to_string(),
            }));
        }
        let output = &split_tx.outputs[0];
        let spk_msg = output.script_public_key.as_ref().ok_or(CoinSelectError::Transaction(
            crate::transaction::TransactionError::InvalidAddress {
                reason: "split.tx.outputs[0].script_public_key missing".to_string(),
            },
        ))?;
        let spk_version = u16::try_from(spk_msg.version).map_err(|_| {
            CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
                reason: "split.tx.outputs[0].script_public_key.version exceeds u16".to_string(),
            })
        })?;
        let spk = ScriptPublicKey::new(spk_version, spk_msg.script.clone().into());

        let split_tx_id = split_consensus_tx_id(split)?;
        utxos.push(Utxo {
            outpoint: outpoint(split_tx_id, 0),
            utxo_entry: UtxoEntry {
                amount: output.value,
                script_public_key: spk,
                block_daa_score: UNACCEPTED_DAA_SCORE,
                is_coinbase: false,
            },
            derivation_path: change_derivation_path.to_string(),
        });
        total_value += output.value;
    }

    // Mirror Go's "estimate fee, then if total < sent, find more"
    // chain (lines 75-91).
    let fee = estimate_fee(cfg, params, &utxos, fee_rate, max_fee, sent_value)?;
    total_value = total_value.saturating_sub(fee);

    if total_value < sent_value {
        let (additional, value_added) =
            more_utxos_for_merge_transaction(cfg, params, &utxos, sent_value - total_value, fee_rate, spare_utxos)?;
        utxos.extend(additional);
        total_value += value_added;
    }

    let mut payments: Vec<Payment> = vec![Payment { address: to_address.clone(), amount: sent_value }];
    if total_value > sent_value {
        payments.push(Payment { address: change_address.clone(), amount: total_value - sent_value });
    }

    Ok(create_unsigned_transaction(&cfg.extended_public_keys, cfg.minimum_signatures, &payments, &utxos)?)
}

/// Verbatim port of Go's `moreUTXOsForMergeTransaction`
/// (`split_transaction.go:320-358`). Iterates `spare_utxos` (the
/// daemon's filtered, sorted-desc UTXO pool) and accumulates
/// additional UTXOs until `total_value_added >= required_amount`.
/// Skips outpoints already in `already_selected_utxos`, mirroring
/// Go's `alreadySelectedUTXOsMap` dedup. Each UTXO contributes
/// `amount - fee_per_input` toward the running total (Go's
/// over-estimate that accounts for the extra signature mass).
fn more_utxos_for_merge_transaction(
    cfg: &WalletConfig,
    params: &Params,
    already_selected_utxos: &[Utxo],
    required_amount: u64,
    fee_rate: f64,
    spare_utxos: &[Utxo],
) -> Result<(Vec<Utxo>, u64), CoinSelectError> {
    let already_keys: Vec<(Vec<u8>, u32)> = already_selected_utxos
        .iter()
        .map(|u| (u.outpoint.transaction_id.as_ref().map(|t| t.bytes.clone()).unwrap_or_default(), u.outpoint.index))
        .collect();

    let fee_per_input = estimate_fee_per_input(cfg, params, fee_rate)?;

    let mut additional: Vec<Utxo> = Vec::new();
    let mut total_value_added: u64 = 0;
    for utxo in spare_utxos {
        let key = (utxo.outpoint.transaction_id.as_ref().map(|t| t.bytes.clone()).unwrap_or_default(), utxo.outpoint.index);
        if already_keys.contains(&key) {
            continue;
        }
        additional.push(utxo.clone());
        total_value_added += utxo.utxo_entry.amount.saturating_sub(fee_per_input);
        if total_value_added >= required_amount {
            break;
        }
    }

    if total_value_added < required_amount {
        return Err(CoinSelectError::InsufficientFunds { required: required_amount, available: total_value_added });
    }
    Ok((additional, total_value_added))
}

/// Compute the kaspa transaction id for a split's `tx` field, the
/// way Go's `consensushashing.TransactionID(splitTransaction.Tx)`
/// does at `split_transaction.go:65-68`. Lifts the wire PST into
/// the consensus-core `Transaction` type and asks the consensus
/// hashing surface for the canonical id.
fn split_consensus_tx_id(pst: &wire::PartiallySignedTransaction) -> Result<[u8; 32], CoinSelectError> {
    let tx_msg = pst.tx.as_ref().ok_or(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
        reason: "pst.tx missing".to_string(),
    }))?;
    // `Transaction::new` already calls `finalize()`, which populates
    // the cached `TransactionId` via the consensus-core canonical
    // hashing surface (`hashing::tx::id` -- the same path Go's
    // `consensushashing.TransactionID` runs).
    let consensus_tx = wire_to_consensus_tx_local(tx_msg)?;
    Ok(consensus_tx.id().as_bytes())
}

/// Local copy of the wire-to-consensus lift used by `split_consensus_tx_id`
/// (the `crate::sign::wire` helper is `pub(crate)` to the sign
/// module's siblings; rather than widening its visibility this
/// function inlines the same shape conversion).
fn wire_to_consensus_tx_local(tx_msg: &wire::TransactionMessage) -> Result<kaspa_consensus_core::tx::Transaction, CoinSelectError> {
    use kaspa_consensus_core::subnets::SubnetworkId;
    use kaspa_consensus_core::tx::{Transaction, TransactionInput, TransactionOutpoint, TransactionOutput};

    let version: u16 = u16::try_from(tx_msg.version).map_err(|_| {
        CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
            reason: format!("tx.version exceeds u16: {}", tx_msg.version),
        })
    })?;

    let subnetwork_bytes = tx_msg
        .subnetwork_id
        .as_ref()
        .ok_or(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
            reason: "tx.subnetwork_id missing".to_string(),
        }))?
        .bytes
        .as_slice();
    if subnetwork_bytes.len() != 20 {
        return Err(CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
            reason: format!("tx.subnetwork_id.bytes len != 20: {}", subnetwork_bytes.len()),
        }));
    }
    let mut sub_arr = [0u8; 20];
    sub_arr.copy_from_slice(subnetwork_bytes);
    let subnetwork_id = SubnetworkId::from_bytes(sub_arr);

    let mut inputs: Vec<TransactionInput> = Vec::with_capacity(tx_msg.inputs.len());
    for input in &tx_msg.inputs {
        let outp = input.previous_outpoint.as_ref().ok_or(CoinSelectError::Transaction(
            crate::transaction::TransactionError::InvalidAddress { reason: "tx.input.previous_outpoint missing".to_string() },
        ))?;
        let txid_bytes = outp.transaction_id.as_ref().ok_or(CoinSelectError::Transaction(
            crate::transaction::TransactionError::InvalidAddress {
                reason: "tx.input.previous_outpoint.transaction_id missing".to_string(),
            },
        ))?;
        let id_arr: [u8; 32] = txid_bytes.bytes.as_slice().try_into().map_err(|_| {
            CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
                reason: format!("tx.input.previous_outpoint.transaction_id.bytes len != 32: {}", txid_bytes.bytes.len()),
            })
        })?;
        let prev = TransactionOutpoint::new(kaspa_consensus_core::Hash::from_bytes(id_arr), outp.index);
        let sig_op_count: u8 = u8::try_from(input.sig_op_count).map_err(|_| {
            CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
                reason: format!("tx.input.sig_op_count exceeds u8: {}", input.sig_op_count),
            })
        })?;
        inputs.push(TransactionInput::new(prev, input.signature_script.clone(), input.sequence, sig_op_count));
    }

    let mut outputs: Vec<TransactionOutput> = Vec::with_capacity(tx_msg.outputs.len());
    for output in &tx_msg.outputs {
        let spk_msg = output.script_public_key.as_ref().ok_or(CoinSelectError::Transaction(
            crate::transaction::TransactionError::InvalidAddress { reason: "tx.output.script_public_key missing".to_string() },
        ))?;
        let spk_version = u16::try_from(spk_msg.version).map_err(|_| {
            CoinSelectError::Transaction(crate::transaction::TransactionError::InvalidAddress {
                reason: format!("tx.output.script_public_key.version exceeds u16: {}", spk_msg.version),
            })
        })?;
        let spk = ScriptPublicKey::new(spk_version, spk_msg.script.clone().into());
        outputs.push(TransactionOutput::new(output.value, spk));
    }

    Ok(Transaction::new(version, inputs, outputs, tx_msg.lock_time, subnetwork_id, tx_msg.gas, tx_msg.payload.clone()))
}
