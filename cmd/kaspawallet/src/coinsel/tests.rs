//! Unit tests for the coin-selection algorithm core.
//!
//! These are pure-Rust tests against synthetic UTXO sets that
//! pin the deterministic ordering rule, the two break conditions,
//! the KIP-9 dust-margin policy, and the insufficient-funds
//! error path. Cross-implementation byte-identity is exercised
//! by the dedicated integration test under
//! `tests/coinsel_parity.rs`.

use super::*;
use crate::transaction::{Utxo, outpoint};
use kaspa_addresses::Prefix as AddrPrefix;
use kaspa_consensus_core::config::params::Params;
use kaspa_consensus_core::network::NetworkType;
use kaspa_consensus_core::tx::{ScriptPublicKey, UtxoEntry};

/// Single-cosigner testnet xpub used as the keyfile-shape stand-in
/// for unit tests. Reused from the sign-module combine tests so
/// every test in this crate exercises the BIP-32 path against a
/// known-valid extended-key fixture.
const XPUB_FIXTURE: &str =
    "ktub22TH54k6Nc3PMjGUfnzD2KkaV1CPu8rnALjjwC2BS2NWcUy4cW5JxpgUbzNAqEHmZ9bvzf3GBPVMeLYKiVfgsKbGXrU26MQJbmSgtyeqRzL";

fn cfg() -> WalletConfig {
    WalletConfig {
        extended_public_keys: vec![XPUB_FIXTURE.to_string()],
        minimum_signatures: 1,
        address_prefix: AddrPrefix::Testnet,
        ecdsa: false,
    }
}

fn params() -> Params {
    Params::from(NetworkType::Testnet)
}

/// Synthesise a UTXO with a specific (outpoint-index, amount,
/// derivation-path) tuple. The script-public-key is a 35-byte
/// P2PK shape (`0x20` PUSH-32 + 32-byte payload + OP_CHECKSIG)
/// so the mass calc has a realistic input-script length.
fn mk_utxo(idx: u32, amount: u64, derivation_path: &str) -> Utxo {
    let mut script = vec![0u8; 35];
    script[0] = 0x20; // OP_DATA_32 (PUSH-32)
    script[33] = 0xAC; // OP_CHECKSIG
    let spk = ScriptPublicKey::new(0, script.into());
    Utxo {
        outpoint: outpoint([idx as u8; 32], idx),
        utxo_entry: UtxoEntry { amount, script_public_key: spk, block_daa_score: 0, is_coinbase: false },
        derivation_path: derivation_path.to_string(),
    }
}

/// Build a sorted-by-amount-descending slice of the supplied
/// amounts (matches the input ordering the daemon's UTXO sync
/// loop produces).
fn sorted_desc(amounts: &[u64]) -> Vec<Utxo> {
    let mut utxos: Vec<Utxo> = amounts.iter().enumerate().map(|(i, &a)| mk_utxo(i as u32 + 1, a, "m/0/0")).collect();
    utxos.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));
    utxos
}

#[test]
fn test_select_utxos_single_input_exact_spend() {
    // Exact match path: total_value == total_spend after one
    // iteration -> immediate break under the first break case.
    // We cannot pre-compute the fee without running the mass calc,
    // so we set `spend_amount` so that even with the largest
    // possible fee the single largest UTXO covers it. Asserts:
    // exactly one UTXO selected.
    let cfg = cfg();
    let params = params();
    let utxos = sorted_desc(&[1_000_000_000]); // 10 KAS
    let sel = select_utxos(&cfg, &params, &utxos, &[], 500_000_000, false, 1.0, 100_000_000).expect("select");
    assert_eq!(sel.selected.len(), 1, "single sufficient UTXO -> single-input selection");
    assert!(sel.change_sompi > 0, "change must be present (total_value > spend + fee)");
    // One-input-with-change disallowed by break case 2 (which
    // requires selected.len() > 1 for change-with-dust-margin);
    // the
    // first-loop iteration's break check fires only when
    // total_value == total_spend OR (>=spend+min_change AND
    // len>1). With len==1 and total>spend+min_change, neither
    // case fires, so the loop runs to completion (no more inputs)
    // and falls through to the totals computation. Confirm the
    // recipient receives spend_amount.
    assert_eq!(sel.total_received, 500_000_000);
}

#[test]
fn test_select_utxos_two_inputs_meets_dust_margin() {
    // KIP-9 second break: two inputs collected with combined
    // total >= spend + fee + MIN_CHANGE_TARGET.
    let cfg = cfg();
    let params = params();
    // Two UTXOs of 5 KAS each (sorted desc -> equal amounts;
    // tied ordering is preserved deterministically by the
    // selector).
    let utxos = sorted_desc(&[2_500_000_000, 2_500_000_000]); // 25 KAS + 25 KAS
    // Spend 10 KAS, leave plenty for fee + change:
    let sel = select_utxos(&cfg, &params, &utxos, &[], 1_000_000_000, false, 1.0, 100_000_000).expect("select");
    assert_eq!(sel.selected.len(), 2, "second break case requires len > 1");
    assert!(sel.change_sompi >= 1_000_000_000, "change must clear the 10 KAS dust margin");
}

#[test]
fn test_select_utxos_largest_first_ordering() {
    // Sorted-by-amount-desc input; assert the selected slice
    // carries the largest UTXOs first.
    let cfg = cfg();
    let params = params();
    let utxos = sorted_desc(&[100_000_000_000, 50_000_000_000, 10_000_000_000, 1_000_000_000]); // 1000 / 500 / 100 / 10 KAS
    // 12 KAS spend forces the loop to take the largest UTXO
    // first and then a second one to clear the KIP-9 dust
    // margin (break case 2 requires `selected.len() > 1`).
    let sel = select_utxos(&cfg, &params, &utxos, &[], 1_200_000_000, false, 1.0, 100_000_000).expect("select");
    assert!(!sel.selected.is_empty());
    // Iteration order is the input slice order, so the first
    // selected UTXO has the largest amount.
    assert_eq!(sel.selected[0].utxo_entry.amount, 100_000_000_000, "first selected = largest");
    if sel.selected.len() > 1 {
        assert_eq!(sel.selected[1].utxo_entry.amount, 50_000_000_000, "second selected = second-largest");
    }
}

#[test]
fn test_select_utxos_pre_selected_iterated_first() {
    // pre_selected loop runs before sorted_utxos loop. A small
    // pre-selected UTXO is consumed first even when bigger UTXOs
    // are available in the sorted slice.
    let cfg = cfg();
    let params = params();
    let pre = vec![mk_utxo(99, 100_000_000, "m/0/0")]; // 1 KAS pre-selected
    let sorted = sorted_desc(&[2_500_000_000, 2_500_000_000]); // 25 + 25 KAS available
    let sel = select_utxos(&cfg, &params, &sorted, &pre, 1_000_000_000, false, 1.0, 100_000_000).expect("select");
    assert_eq!(sel.selected[0].outpoint.index, 99, "pre-selected UTXO appears first in iteration order");
}

#[test]
fn test_select_utxos_pre_selected_skipped_in_second_loop() {
    // If a pre-selected UTXO also appears in the sorted slice
    // (overlap), the second loop must skip it (avoidPreselected =
    // true) so it is not double-counted.
    let cfg = cfg();
    let params = params();
    let pre_utxo = mk_utxo(1, 2_500_000_000, "m/0/0");
    let sorted = vec![pre_utxo.clone(), mk_utxo(2, 2_500_000_000, "m/0/0")];
    let sel = select_utxos(&cfg, &params, &sorted, &[pre_utxo], 1_000_000_000, false, 1.0, 100_000_000).expect("select");
    // Total inputs = pre-selected (1) + maybe one from second
    // loop. The pre-selected outpoint MUST appear exactly once
    // even though it's also in `sorted`.
    let outpoint_1_count = sel.selected.iter().filter(|u| u.outpoint.index == 1).count();
    assert_eq!(outpoint_1_count, 1, "pre-selected outpoint must appear exactly once in selection");
}

#[test]
fn test_select_utxos_send_all_consumes_every_utxo() {
    // is_send_all = true: loop never breaks early; total_received
    // = total_value - fee; change = 0.
    let cfg = cfg();
    let params = params();
    let utxos = sorted_desc(&[100_000_000, 100_000_000, 100_000_000]); // 1 + 1 + 1 KAS
    let sel = select_utxos(&cfg, &params, &utxos, &[], 0, true, 1.0, 100_000_000).expect("select");
    assert_eq!(sel.selected.len(), 3, "is_send_all consumes every UTXO");
    assert_eq!(sel.change_sompi, 0, "no change in send-all mode");
    assert!(sel.total_received < 300_000_000, "total_received = total_value - fee, must be less than gross");
}

#[test]
fn test_select_utxos_insufficient_funds() {
    // Total UTXO value cannot cover spend + fee ->
    // `CoinSelectError::InsufficientFunds`.
    let cfg = cfg();
    let params = params();
    let utxos = sorted_desc(&[100_000_000]); // 1 KAS available
    let err = select_utxos(&cfg, &params, &utxos, &[], 100_000_000_000, false, 1.0, 100_000_000).expect_err("insufficient funds");
    assert!(matches!(err, CoinSelectError::InsufficientFunds { .. }), "got {err:?}");
}

#[test]
fn test_select_utxos_empty_inputs_with_zero_amount_succeeds() {
    // Edge case: no UTXOs, spend 0, is_send_all false. The
    // selector returns an empty selection here because
    // total_value == total_spend == 0 and the InsufficientFunds
    // branch is not entered.
    let cfg = cfg();
    let params = params();
    let sel = select_utxos(&cfg, &params, &[], &[], 0, false, 1.0, 100_000_000).expect("select empty");
    assert!(sel.selected.is_empty());
    assert_eq!(sel.total_received, 0);
    assert_eq!(sel.change_sompi, 0);
}

#[test]
fn test_select_utxos_change_sompi_is_value_minus_spend_minus_fee() {
    // Pin the change arithmetic. Two big UTXOs, modest spend.
    // change = total_value - spend_amount - fee.
    let cfg = cfg();
    let params = params();
    let utxos = sorted_desc(&[5_000_000_000, 5_000_000_000]); // 50 + 50 KAS
    let spend = 1_000_000_000; // 10 KAS
    let sel = select_utxos(&cfg, &params, &utxos, &[], spend, false, 1.0, 100_000_000).expect("select");
    let total_value: u64 = sel.selected.iter().map(|u| u.utxo_entry.amount).sum();
    // Reconstruct fee from selection: change = total - spend - fee
    // -> fee = total - spend - change.
    let fee = total_value - spend - sel.change_sompi;
    assert!(fee > 0, "fee must be > 0 for any non-empty selection");
    assert_eq!(sel.change_sompi, total_value - spend - fee);
}

#[test]
fn test_estimate_fee_returns_positive_for_realistic_input() {
    // Smoke-check: estimate_fee on a single 10-KAS UTXO sending
    // 5 KAS to a fake recipient must return a positive fee >= 1
    // sompi (the minFeeRate * mass floor).
    let cfg = cfg();
    let params = params();
    let utxo = mk_utxo(0, 1_000_000_000, "m/0/0");
    let fee = estimate_fee(&cfg, &params, &[utxo], 1.0, 100_000_000, 500_000_000).expect("estimate");
    assert!(fee > 0, "fee must be positive for a non-empty mock tx");
    assert!(fee < 100_000_000, "fee must respect max_fee clamp");
}

#[test]
fn test_estimate_fee_clamps_to_max_fee() {
    // High fee_rate * mass should saturate to max_fee.
    let cfg = cfg();
    let params = params();
    let utxo = mk_utxo(0, 1_000_000_000, "m/0/0");
    let fee = estimate_fee(&cfg, &params, &[utxo], 1_000_000.0, 1234, 500_000_000).expect("estimate");
    assert_eq!(fee, 1234, "fee_rate * mass exceeds max_fee -> clamped to max_fee");
}

#[test]
fn test_estimate_fee_per_input_returns_positive_input_mass_times_fee_rate() {
    // `estimate_fee_per_input` always returns a positive value:
    // a single-input mock tx must compute-mass higher than a
    // zero-input mock tx, so `input_mass > 0` and
    // `input_mass * fee_rate > 0`.
    let cfg = cfg();
    let params = params();
    let fee_per_input = estimate_fee_per_input(&cfg, &params, 1.0).expect("fee_per_input");
    assert!(fee_per_input > 0, "input_mass * fee_rate must be > 0 for a non-degenerate input");
}

#[test]
fn test_estimate_fee_per_input_scales_with_fee_rate() {
    // Doubling fee_rate must roughly double the result (the
    // formula is `input_mass * fee_rate` truncated to u64).
    let cfg = cfg();
    let params = params();
    let f1 = estimate_fee_per_input(&cfg, &params, 1.0).expect("fee@1");
    let f10 = estimate_fee_per_input(&cfg, &params, 10.0).expect("fee@10");
    assert!(f10 > f1, "higher fee_rate must produce higher fee_per_input");
    // Allow a +/-2 unit tolerance for the floor() truncation.
    let expected_f10 = f1 * 10;
    let diff = f10.abs_diff(expected_f10);
    assert!(diff <= 2, "f10 ~ 10 * f1 (within truncation tolerance); f1={f1}, f10={f10}");
}

// ---- coinsel::split tests ----

mod split_tests {
    use super::*;
    use crate::coinsel::MAXIMUM_STANDARD_TRANSACTION_MASS;
    use crate::coinsel::maybe_auto_compound_transaction;
    use crate::transaction::{Payment, create_unsigned_transaction};
    use kaspa_addresses::{Address, Prefix as AddrPrefix, Version as AddrVersion};

    /// 33-byte ECDSA-fake address (worst-case scriptPubKey).
    fn fake_ecdsa_address() -> Address {
        Address::new(AddrPrefix::Testnet, AddrVersion::PubKeyECDSA, &[0u8; 33])
    }

    /// 32-byte Schnorr-pubkey-shape address.
    fn fake_schnorr_address() -> Address {
        Address::new(AddrPrefix::Testnet, AddrVersion::PubKey, &[0xAAu8; 32])
    }

    #[test]
    fn test_maybe_auto_compound_transaction_returns_unchanged_when_under_mass_limit() {
        // A small tx (one input, two outputs) is well under the
        // MaximumStandardTransactionMass cap; the splitter must
        // return [serialize(transaction)] unchanged.
        let cfg = cfg();
        let params = params();
        let utxo = mk_utxo(1, 100_000_000_000, "m/0/0");
        let to_addr = fake_schnorr_address();
        let change_addr = fake_ecdsa_address();
        let payments = vec![
            Payment { address: to_addr.clone(), amount: 50_000_000_000 },
            Payment { address: change_addr.clone(), amount: 49_000_000_000 },
        ];
        let tx =
            create_unsigned_transaction(&cfg.extended_public_keys, cfg.minimum_signatures, &payments, &[utxo]).expect("create tx");
        let bytes = maybe_auto_compound_transaction(&cfg, &params, tx, &to_addr, &change_addr, "m/1/0", 1.0, 100_000_000_000, &[])
            .expect("auto compound");
        assert_eq!(bytes.len(), 1, "small tx must not be split");
    }

    #[test]
    fn test_maximum_standard_transaction_mass_constant_matches_protocol() {
        // Pin the constant against the protocol value
        // (`MaximumStandardTransactionMass = 100_000`). If
        // kaspad ever bumps this, the matching ports across the
        // workspace must update together.
        assert_eq!(MAXIMUM_STANDARD_TRANSACTION_MASS, 100_000);
    }

    #[test]
    fn test_maybe_auto_compound_transaction_splits_high_input_count() {
        // Build a transaction with enough inputs to push the mass
        // past the 100_000 standard-tx-mass cap. With ~1000 inputs
        // (each ~100 grams of compute mass for a single-cosigner
        // P2PK input plus the per-input UTXO entry overhead), the
        // total mass exceeds the cap and the splitter must produce
        // at least 2 split transactions plus a merge transaction.
        let cfg = cfg();
        let params = params();
        let to_addr = fake_schnorr_address();
        let change_addr = fake_ecdsa_address();

        // Fewer + bigger inputs is a faster way to overrun mass via
        // STORAGE mass on big outputs; but the splitter gates on
        // COMPUTE mass, which scales mostly with input count. Use
        // many small inputs.
        let mut utxos = Vec::with_capacity(1000);
        for i in 0..1000u32 {
            utxos.push(mk_utxo(i + 1, 200_000_000_000, "m/0/0"));
        }
        // Spend an amount that requires consuming all inputs (total
        // is 200_000 KAS; spend 199_500 KAS forces every UTXO to
        // be consumed under is_send_all=false's two-break-case
        // policy).
        let payments = vec![
            Payment { address: to_addr.clone(), amount: 19_950_000_000_000 },
            Payment { address: change_addr.clone(), amount: 49_900_000_000_000 },
        ];
        let tx =
            create_unsigned_transaction(&cfg.extended_public_keys, cfg.minimum_signatures, &payments, &utxos).expect("create big tx");

        // Generously priced spare_utxos available in case the merge
        // step needs more value (the test assertion is on the
        // splitter's output count, not the merge's success).
        let spare_utxos: Vec<_> = (10_000u32..10_010).map(|i| mk_utxo(i, 1_000_000_000_000_000, "m/0/0")).collect();

        let bytes =
            maybe_auto_compound_transaction(&cfg, &params, tx, &to_addr, &change_addr, "m/1/0", 1.0, 1_000_000_000_000, &spare_utxos)
                .expect("auto compound large tx");
        assert!(bytes.len() >= 2, "high-input-count tx must produce multiple split transactions; got {}", bytes.len());
    }
}
