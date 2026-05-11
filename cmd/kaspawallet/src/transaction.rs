//! Verbatim port of `libkaspawallet/transaction.go`'s
//! `CreateUnsignedTransaction` primitive (the `Payment`/`UTXO`/
//! `CreateUnsignedTransaction` triplet that the Go daemon and CLI
//! use to assemble an unsigned `PartiallySignedTransaction` from a
//! coin-selection result).
//!
//! Source: https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/libkaspawallet/transaction.go#L31
//! (`CreateUnsignedTransaction` -> `sortPublicKeys` -> internal
//! `createUnsignedTransaction`). The Go primitive is the only
//! producer of unsigned PSTs both daemon-side and CLI-side, so a
//! line-for-line port is the load-bearing prerequisite for the
//! cross-binary wire-byte-identity property the cross-wallet
//! multisig interop and side-by-side send / sweep parity tests
//! depend on.
//!
//! Reuse-existing-crates discipline: the BIP-32 derivation comes
//! from `kaspa_bip32::ExtendedPublicKey` (Go's
//! `bip32.DeserializeExtendedKey` + `DeriveFromPath`); the
//! script-pubkey emission for each payment comes from
//! `kaspa_txscript::pay_to_address_script` (Go's
//! `txscript.PayToAddrScript`); the `SUBNETWORK_ID_NATIVE`
//! constant comes from `kaspa_consensus_core::subnets` (Go's
//! `subnetworks.SubnetworkIDNative`). No new wire shape, no
//! re-derivation primitive, no rolled crypto.

use kaspa_addresses::Address;
use kaspa_bip32::{DerivationPath, ExtendedPublicKey, secp256k1::PublicKey};
use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
use kaspa_consensus_core::tx::UtxoEntry;
use kaspa_txscript::pay_to_address_script;
use thiserror::Error;

use crate::serialization::wire;

/// Maximum supported transaction-version field. Mirrors Go's
/// `constants.MaxTransactionVersion = 0`
/// (`domain/consensus/utils/constants/constants.go:10`).
const MAX_TRANSACTION_VERSION: u32 = 0;

/// Length of the kaspa subnetwork-id field on the wire (20 bytes).
const SUBNETWORK_ID_LEN: usize = 20;

/// Length of a kaspa transaction-id field on the wire (32 bytes).
const TRANSACTION_ID_LEN: usize = 32;

/// Recipient payment in a [`create_unsigned_transaction`] call.
/// Mirrors Go's `libkaspawallet.Payment` struct
/// (`libkaspawallet/transaction.go` lines 17-20).
#[derive(Clone, Debug)]
pub struct Payment {
    pub address: Address,
    pub amount: u64,
}

/// UTXO + derivation path bundle consumed by
/// [`create_unsigned_transaction`] and the coin-selection layer.
/// Mirrors Go's `libkaspawallet.UTXO` struct
/// (`libkaspawallet/transaction.go` lines 22-28). Carries a
/// [`UtxoEntry`] from `kaspa_consensus_core::tx` directly so the
/// wallet daemon can populate it from `kaspad`'s
/// `getUtxosByAddresses` response without a synthetic conversion
/// step.
#[derive(Clone, Debug)]
pub struct Utxo {
    pub outpoint: wire::Outpoint,
    pub utxo_entry: UtxoEntry,
    pub derivation_path: String,
}

/// Errors returned by [`create_unsigned_transaction`] when the
/// caller-supplied inputs cannot be assembled into a wire PST.
#[derive(Debug, Error)]
pub enum TransactionError {
    /// One of the cosigner xpub strings does not parse via
    /// `kaspa_bip32::ExtendedPublicKey::from_str`. Mirrors Go's
    /// `bip32.DeserializeExtendedKey` error path.
    #[error("invalid extended public key: {reason}")]
    InvalidExtendedPublicKey { reason: String },

    /// The per-UTXO derivation-path string does not parse via
    /// `kaspa_bip32::DerivationPath::from_str`. Mirrors Go's
    /// `extendedKey.DeriveFromPath(path)` error path.
    #[error("invalid derivation path '{path}': {reason}")]
    InvalidDerivationPath { path: String, reason: String },

    /// The BIP-32 derivation step failed (e.g. hardened-component
    /// requested via an xpub).
    #[error("BIP-32 derivation failed for path '{path}': {reason}")]
    DeriveFailed { path: String, reason: String },

    /// One of the recipient addresses produces a zero-length
    /// script-public-key from `kaspa_txscript::pay_to_address_script`
    /// (well-formed addresses cannot trigger this; the variant
    /// exists for defense-in-depth).
    #[error("invalid recipient address: {reason}")]
    InvalidAddress { reason: String },
}

/// Lexicographic in-place sort of cosigner xpub strings. Mirrors
/// Go's `sortPublicKeys` at
/// `libkaspawallet/keypair.go:135` (`sort.Slice` +
/// `strings.Compare(extendedPublicKeys[i], extendedPublicKeys[j])
/// < 0`). The sort is the load-bearing determinism step: every
/// per-input pair-construction loop iterates the sorted xpub list
/// in the same order, so two callers with the same logical xpub
/// set produce byte-identical PSTs regardless of input ordering.
pub fn sort_extended_public_keys(extended_public_keys: &mut [String]) {
    extended_public_keys.sort();
}

/// Build an unsigned [`wire::PartiallySignedTransaction`] from a
/// keyfile's xpub set, the per-input UTXOs the coin selector
/// returned, and the per-output payments the daemon assembled.
///
/// Mirrors Go's `CreateUnsignedTransaction` +
/// `createUnsignedTransaction` pair (`libkaspawallet/transaction.go`
/// lines 31-159) line-for-line:
///
/// 1. Sort the `extendedPublicKeys` slice in-place by lex order
///    (Go: `sortPublicKeys`).
/// 2. For each selected UTXO, build a `PartiallySignedInput` whose
///    `pub_key_signature_pairs` carries one empty `PubKeySignaturePair`
///    per cosigner xpub. Each pair's `extended_public_key` is the
///    cosigner's xpub derived to the UTXO's `derivation_path`
///    (Go: `extendedKey.DeriveFromPath(utxo.DerivationPath)` +
///    `derivedKey.String()`).
/// 3. For each payment, build a `wire::TransactionOutput` whose
///    `script_public_key` is `kaspa_txscript::pay_to_address_script(addr)`.
/// 4. Wrap the inputs/outputs in a `wire::TransactionMessage` with
///    `version = MaxTransactionVersion (= 0)`, `lock_time = 0`,
///    `subnetwork_id = SUBNETWORK_ID_NATIVE`, `gas = 0`,
///    `payload = []`.
///
/// The returned `wire::PartiallySignedTransaction` serializes via
/// [`crate::serialization::serialize_partially_signed_transaction`]
/// into a byte sequence that is byte-identical to what Go's
/// `serialization.SerializePartiallySignedTransaction` would
/// produce for the same inputs (proto3 deterministic encoding
/// + identical field ordering on both sides).
pub fn create_unsigned_transaction(
    extended_public_keys: &[String],
    minimum_signatures: u32,
    payments: &[Payment],
    selected_utxos: &[Utxo],
) -> Result<wire::PartiallySignedTransaction, TransactionError> {
    let mut sorted_xpubs: Vec<String> = extended_public_keys.to_vec();
    sort_extended_public_keys(&mut sorted_xpubs);

    let mut inputs: Vec<wire::TransactionInput> = Vec::with_capacity(selected_utxos.len());
    let mut partially_signed_inputs: Vec<wire::PartiallySignedInput> = Vec::with_capacity(selected_utxos.len());

    for utxo in selected_utxos {
        let path = parse_derivation_path(&utxo.derivation_path)?;
        let pairs = build_pair_set(&sorted_xpubs, &path, &utxo.derivation_path)?;

        inputs.push(wire::TransactionInput {
            previous_outpoint: Some(utxo.outpoint.clone()),
            signature_script: Vec::new(),
            sequence: 0,
            sig_op_count: 0,
        });

        partially_signed_inputs.push(wire::PartiallySignedInput {
            redeem_script: Vec::new(),
            prev_output: Some(wire::TransactionOutput {
                value: utxo.utxo_entry.amount,
                script_public_key: Some(wire::ScriptPublicKey {
                    version: u32::from(utxo.utxo_entry.script_public_key.version()),
                    script: utxo.utxo_entry.script_public_key.script().to_vec(),
                }),
            }),
            minimum_signatures,
            pub_key_signature_pairs: pairs,
            derivation_path: utxo.derivation_path.clone(),
        });
    }

    let outputs: Vec<wire::TransactionOutput> = payments.iter().map(payment_to_output).collect::<Result<_, _>>()?;

    let mut subnetwork = vec![0u8; SUBNETWORK_ID_LEN];
    subnetwork.copy_from_slice(SUBNETWORK_ID_NATIVE.as_ref());

    let tx = wire::TransactionMessage {
        version: MAX_TRANSACTION_VERSION,
        inputs,
        outputs,
        lock_time: 0,
        subnetwork_id: Some(wire::SubnetworkId { bytes: subnetwork }),
        gas: 0,
        payload: Vec::new(),
    };

    Ok(wire::PartiallySignedTransaction { tx: Some(tx), partially_signed_inputs })
}

fn parse_derivation_path(raw: &str) -> Result<DerivationPath, TransactionError> {
    raw.parse::<DerivationPath>().map_err(|e| TransactionError::InvalidDerivationPath { path: raw.to_string(), reason: e.to_string() })
}

fn build_pair_set(
    sorted_xpubs: &[String],
    path: &DerivationPath,
    raw_path: &str,
) -> Result<Vec<wire::PubKeySignaturePair>, TransactionError> {
    let mut pairs: Vec<wire::PubKeySignaturePair> = Vec::with_capacity(sorted_xpubs.len());
    for xpub in sorted_xpubs {
        let parsed: ExtendedPublicKey<PublicKey> =
            xpub.parse().map_err(|e: kaspa_bip32::Error| TransactionError::InvalidExtendedPublicKey { reason: e.to_string() })?;
        let prefix = pick_prefix(xpub);
        let derived = parsed
            .derive_path(path)
            .map_err(|e| TransactionError::DeriveFailed { path: raw_path.to_string(), reason: e.to_string() })?;
        pairs.push(wire::PubKeySignaturePair { extended_pub_key: derived.to_string(Some(prefix)), signature: Vec::new() });
    }
    Ok(pairs)
}

/// Length of the xpub textual prefix (e.g. `"kpub"`, `"ktub"`)
/// preserved when re-emitting a derived key's textual form. Same
/// rule the sign module's [`crate::sign::derive`] helper uses to
/// avoid hardcoding a network in the derived-pubkey re-emission.
const XPUB_PREFIX_LEN: usize = 4;

fn pick_prefix(xpub: &str) -> kaspa_bip32::Prefix {
    let prefix_str: &str = if xpub.len() >= XPUB_PREFIX_LEN { &xpub[..XPUB_PREFIX_LEN] } else { xpub };
    kaspa_bip32::Prefix::try_from(prefix_str).unwrap_or(kaspa_bip32::Prefix::KPUB)
}

fn payment_to_output(payment: &Payment) -> Result<wire::TransactionOutput, TransactionError> {
    let spk = pay_to_address_script(&payment.address);
    if spk.script().is_empty() {
        return Err(TransactionError::InvalidAddress { reason: format!("address {} produced empty script", payment.address) });
    }
    Ok(wire::TransactionOutput {
        value: payment.amount,
        script_public_key: Some(wire::ScriptPublicKey { version: u32::from(spk.version()), script: spk.script().to_vec() }),
    })
}

/// Helper for tests and the coin-selection layer: construct a
/// [`wire::Outpoint`] from a 32-byte transaction id + a u32 index
/// without going through proto field-by-field construction.
pub fn outpoint(transaction_id: [u8; TRANSACTION_ID_LEN], index: u32) -> wire::Outpoint {
    wire::Outpoint { transaction_id: Some(wire::TransactionId { bytes: transaction_id.to_vec() }), index }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::serialize_partially_signed_transaction;
    use kaspa_addresses::{Address, Prefix as AddrPrefix, Version as AddrVersion};
    use kaspa_consensus_core::tx::ScriptPublicKey;

    // Two valid testnet xpub strings reused from the sign-module
    // combine tests. Lex-ordered: `XPUB_LO` < `XPUB_HI`.
    const XPUB_LO: &str =
        "ktub22TH54k6Nc3PMjGUfnzD2KkaV1CPu8rnALjjwC2BS2NWcUy4cW5JxpgUbzNAqEHmZ9bvzf3GBPVMeLYKiVfgsKbGXrU26MQJbmSgtyeqRzL";
    const XPUB_HI: &str =
        "ktub23t7RjF5AQHwkhCaiTAoTdzkgvXGAbfL8jPre2FhPzDXqVrEB3AkRmfxtLwbGAq46ShaGdsRToeKEcJUeuy17Vh8QmRgfdSqZJGBJREKP44";

    fn dummy_address(byte: u8) -> Address {
        Address::new(AddrPrefix::Testnet, AddrVersion::PubKey, &[byte; 32])
    }

    fn dummy_utxo(idx: u32, amount: u64, derivation_path: &str) -> Utxo {
        let spk = ScriptPublicKey::new(0, vec![0u8; 35].into());
        Utxo {
            outpoint: outpoint([idx as u8; TRANSACTION_ID_LEN], idx),
            utxo_entry: UtxoEntry { amount, script_public_key: spk, block_daa_score: 0, is_coinbase: false },
            derivation_path: derivation_path.to_string(),
        }
    }

    #[test]
    fn test_sort_extended_public_keys_lex() {
        // Mirror Go's strings.Compare(...) < 0 ordering: ASCII
        // lex; "a" < "b" < "z".
        let mut keys = vec!["zeta".to_string(), "alpha".to_string(), "mu".to_string()];
        sort_extended_public_keys(&mut keys);
        assert_eq!(keys, vec!["alpha".to_string(), "mu".to_string(), "zeta".to_string()]);
    }

    #[test]
    fn test_sort_extended_public_keys_already_sorted_is_noop() {
        let mut keys = vec!["a".to_string(), "b".to_string()];
        sort_extended_public_keys(&mut keys);
        assert_eq!(keys, vec!["a".to_string(), "b".to_string()]);
    }

    #[test]
    fn test_create_unsigned_transaction_emits_native_subnetwork_and_v0() {
        let utxo = dummy_utxo(0, 10_000_000, "m/0/0");
        let payments = vec![Payment { address: dummy_address(0xAA), amount: 5_000_000 }];
        let pst = create_unsigned_transaction(&[XPUB_LO.to_string()], 1, &payments, &[utxo]).expect("create");
        let tx = pst.tx.as_ref().expect("tx populated");
        assert_eq!(tx.version, MAX_TRANSACTION_VERSION, "version field must mirror Go's MaxTransactionVersion = 0");
        assert_eq!(tx.lock_time, 0, "lock_time always 0 in CreateUnsignedTransaction");
        assert_eq!(tx.gas, 0, "gas always 0 in CreateUnsignedTransaction");
        assert!(tx.payload.is_empty(), "payload always empty in CreateUnsignedTransaction");
        let subnetwork = tx.subnetwork_id.as_ref().expect("subnetworkId set");
        assert_eq!(subnetwork.bytes, vec![0u8; SUBNETWORK_ID_LEN], "SUBNETWORK_ID_NATIVE is all zeros");
    }

    #[test]
    fn test_create_unsigned_transaction_inputs_and_outputs_count_match() {
        let utxos = vec![dummy_utxo(1, 5_000_000, "m/0/0"), dummy_utxo(2, 3_000_000, "m/0/1"), dummy_utxo(3, 2_000_000, "m/0/2")];
        let payments = vec![
            Payment { address: dummy_address(0xBB), amount: 6_000_000 },
            Payment { address: dummy_address(0xCC), amount: 3_900_000 },
        ];
        let pst = create_unsigned_transaction(&[XPUB_LO.to_string()], 1, &payments, &utxos).expect("create");
        let tx = pst.tx.as_ref().expect("tx populated");
        assert_eq!(tx.inputs.len(), utxos.len(), "one tx input per selected UTXO");
        assert_eq!(tx.outputs.len(), payments.len(), "one tx output per payment");
        assert_eq!(pst.partially_signed_inputs.len(), utxos.len(), "one PSI per UTXO");
        for (i, psi) in pst.partially_signed_inputs.iter().enumerate() {
            assert_eq!(psi.derivation_path, utxos[i].derivation_path);
            assert_eq!(psi.minimum_signatures, 1);
            assert_eq!(psi.pub_key_signature_pairs.len(), 1, "1 cosigner xpub -> 1 pair per PSI");
            let prev = psi.prev_output.as_ref().expect("prev_output populated");
            assert_eq!(prev.value, utxos[i].utxo_entry.amount);
        }
    }

    #[test]
    fn test_create_unsigned_transaction_sorts_xpubs_lex_order() {
        // Two xpubs deliberately presented in reverse-lex order to
        // the function. The PSI's pair order MUST follow lex order
        // (XPUB_LO first, XPUB_HI second) regardless of
        // caller input ordering, mirroring Go's sortPublicKeys
        // pre-loop sort.
        let utxo = dummy_utxo(0, 10_000_000, "m/0/0");
        let payments = vec![Payment { address: dummy_address(0xAA), amount: 5_000_000 }];

        let reversed = vec![XPUB_HI.to_string(), XPUB_LO.to_string()];
        let pst_a = create_unsigned_transaction(&reversed, 2, &payments, std::slice::from_ref(&utxo)).expect("create reversed");

        let sorted = vec![XPUB_LO.to_string(), XPUB_HI.to_string()];
        let pst_b = create_unsigned_transaction(&sorted, 2, &payments, &[utxo]).expect("create sorted");

        let bytes_a = serialize_partially_signed_transaction(&pst_a).expect("encode a");
        let bytes_b = serialize_partially_signed_transaction(&pst_b).expect("encode b");
        assert_eq!(bytes_a, bytes_b, "sort_extended_public_keys must produce same bytes regardless of caller input order");
    }

    #[test]
    fn test_create_unsigned_transaction_fails_on_invalid_xpub() {
        let utxo = dummy_utxo(0, 10_000_000, "m/0/0");
        let payments = vec![Payment { address: dummy_address(0xAA), amount: 5_000_000 }];
        let err = create_unsigned_transaction(&["not-a-real-xpub".to_string()], 1, &payments, &[utxo]).expect_err("must reject");
        assert!(matches!(err, TransactionError::InvalidExtendedPublicKey { .. }), "got {err:?}");
    }

    #[test]
    fn test_create_unsigned_transaction_fails_on_invalid_derivation_path() {
        let mut utxo = dummy_utxo(0, 10_000_000, "m/0/0");
        utxo.derivation_path = "not/a/path".to_string();
        let payments = vec![Payment { address: dummy_address(0xAA), amount: 5_000_000 }];
        let err = create_unsigned_transaction(&[XPUB_LO.to_string()], 1, &payments, &[utxo]).expect_err("must reject");
        assert!(matches!(err, TransactionError::InvalidDerivationPath { .. }), "got {err:?}");
    }

    #[test]
    fn test_create_unsigned_transaction_zero_inputs_zero_outputs_is_valid_shape() {
        // Mirrors Go's behavior when called with empty payments + empty
        // selected_utxos (exercised by mass-calc helpers in the
        // daemon's split_transaction.go path). Result is a syntactically
        // valid PST with zero-length input/output vectors.
        let pst = create_unsigned_transaction(&[XPUB_LO.to_string()], 1, &[], &[]).expect("create empty");
        let tx = pst.tx.expect("tx populated");
        assert!(tx.inputs.is_empty());
        assert!(tx.outputs.is_empty());
        assert!(pst.partially_signed_inputs.is_empty());
    }
}
