//! Multisig partial-signature combination + final-signature-script
//! assembly. Mirrors the Go reference at
//! `https://github.com/kaspanet/kaspad/blob/master/cmd/kaspawallet/libkaspawallet/transaction.go#L188`
//! (`ExtractTransactionDeserialized`,
//! `partiallySignedInputMultisigRedeemScript`,
//! `multiSigRedeemScript`).
//!
//! Phase 1 contract:
//!
//! - Consumes a fully-signed (or junk-filled, for mass estimation)
//!   `PartiallySignedTransaction` -- every input's
//!   `PubKeySignaturePairs` carries the required number of
//!   `Signature` byte blobs.
//! - Produces a consensus-core `Transaction` whose
//!   `inputs[i].signature_script` is the on-chain-broadcastable
//!   sigscript, built the same way the Go reference's
//!   `txscript.NewScriptBuilder()...Script()` chain builds it.
//! - For single-cosigner inputs the sigscript is one PUSHDATA of
//!   the signature blob; for multisig inputs the sigscript is N
//!   PUSHDATA signatures followed by one PUSHDATA of the redeem
//!   script.
//!
//! Reuse-existing-crates discipline observed end-to-end:
//!
//! - `kaspa_bip32::ExtendedPublicKey` for deserializing each
//!   `pair.extended_pub_key` and extracting its serialized public
//!   key.
//! - `kaspa_txscript::script_builder::ScriptBuilder` for every
//!   PUSHDATA wrapping (so length prefixes match Go's
//!   `txscript.NewScriptBuilder().AddData(...)` byte-for-byte).
//! - `kaspa_txscript::standard::multisig::{multisig_redeem_script,
//!   multisig_redeem_script_ecdsa}` for the redeem-script
//!   construction (the same primitive `kaspa-txscript`'s own
//!   multisig tests consume).

use kaspa_bip32::ExtendedPublicKey;
use kaspa_consensus_core::tx::{Transaction, TransactionInput};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_txscript::standard::{MultisigCreateError, multisig_redeem_script, multisig_redeem_script_ecdsa};

use super::SignError;
use super::wire::wire_to_consensus_tx;
use crate::serialization::wire;

/// Schnorr (BIP-340) x-only serialized public-key length.
const SCHNORR_PUBKEY_LEN: usize = 32;

/// Compressed ECDSA serialized public-key length.
const ECDSA_PUBKEY_LEN: usize = 33;

/// Assemble the on-chain `Transaction` from a fully-collected (or
/// junk-filled) PST. Mirrors the Go
/// `ExtractTransactionDeserialized(pst, ecdsa)` end-to-end.
///
/// `ecdsa` controls the redeem-script's opcode + pubkey form for
/// multisig inputs (`OpCheckMultiSig` + 32-byte Schnorr pubkeys vs
/// `OpCheckMultiSigECDSA` + 33-byte compressed pubkeys). For
/// single-cosigner inputs the flag is unused (the sigscript is one
/// PUSHDATA of the signature only).
pub fn extract_transaction(pst: &wire::PartiallySignedTransaction, ecdsa: bool) -> Result<Transaction, SignError> {
    let tx_msg = pst.tx.as_ref().ok_or(SignError::Missing("PartiallySignedTransaction.tx"))?;
    let mut consensus_tx = wire_to_consensus_tx(tx_msg)?;

    let mut new_inputs: Vec<TransactionInput> = Vec::with_capacity(consensus_tx.inputs.len());
    for (idx, psi) in pst.partially_signed_inputs.iter().enumerate() {
        let consensus_input = consensus_tx.inputs.get(idx).ok_or(SignError::Missing("PartiallySignedTransaction.tx.inputs[idx]"))?;
        let is_multisig = psi.pub_key_signature_pairs.len() > 1;
        let sig_script =
            if is_multisig { build_multisig_signature_script(psi, ecdsa)? } else { build_singlekey_signature_script(psi)? };
        let sig_op_count = u8::try_from(psi.pub_key_signature_pairs.len()).map_err(|_| SignError::Invalid {
            field: "PartiallySignedInput.pairs",
            reason: format!("count {} exceeds u8::MAX", psi.pub_key_signature_pairs.len()),
        })?;
        new_inputs.push(TransactionInput::new(consensus_input.previous_outpoint, sig_script, consensus_input.sequence, sig_op_count));
    }

    consensus_tx = Transaction::new(
        consensus_tx.version,
        new_inputs,
        consensus_tx.outputs.clone(),
        consensus_tx.lock_time,
        consensus_tx.subnetwork_id.clone(),
        consensus_tx.gas,
        consensus_tx.payload.clone(),
    );
    Ok(consensus_tx)
}

fn build_singlekey_signature_script(psi: &wire::PartiallySignedInput) -> Result<Vec<u8>, SignError> {
    let pair = psi.pub_key_signature_pairs.first().ok_or(SignError::Missing("PartiallySignedInput.pubKeySignaturePairs[0]"))?;
    if pair.signature.is_empty() {
        return Err(SignError::Invalid {
            field: "PubKeySignaturePair.signature",
            reason: "single-cosigner sigscript: signature missing".to_owned(),
        });
    }
    let mut builder = ScriptBuilder::new();
    builder.add_data(&pair.signature).map_err(script_builder_to_sign_err)?;
    Ok(builder.drain())
}

fn build_multisig_signature_script(psi: &wire::PartiallySignedInput, ecdsa: bool) -> Result<Vec<u8>, SignError> {
    let mut builder = ScriptBuilder::new();
    let mut sig_count: u32 = 0;
    for pair in &psi.pub_key_signature_pairs {
        if pair.signature.is_empty() {
            continue;
        }
        builder.add_data(&pair.signature).map_err(script_builder_to_sign_err)?;
        sig_count += 1;
    }
    if sig_count < psi.minimum_signatures {
        return Err(SignError::Invalid {
            field: "PartiallySignedInput",
            reason: format!("missing {} signature(s)", psi.minimum_signatures - sig_count),
        });
    }

    let redeem_script = redeem_script_for_input(psi, ecdsa)?;
    builder.add_data(&redeem_script).map_err(script_builder_to_sign_err)?;
    Ok(builder.drain())
}

/// Build the redeem script bound to a multisig input's pair set.
/// Mirrors Go `partiallySignedInputMultisigRedeemScript`:
/// extracts each pair's `extended_pub_key`, deserializes it, takes
/// its serialized public key (32-byte x-only for Schnorr, 33-byte
/// compressed for ECDSA), and builds the M-of-N redeem script via
/// `kaspa_txscript::standard::multisig::multisig_redeem_script*`.
fn redeem_script_for_input(psi: &wire::PartiallySignedInput, ecdsa: bool) -> Result<Vec<u8>, SignError> {
    let required = psi.minimum_signatures as usize;
    if ecdsa {
        let pubkeys = psi
            .pub_key_signature_pairs
            .iter()
            .map(|pair| ecdsa_serialized_pubkey_from_xpub(&pair.extended_pub_key))
            .collect::<Result<Vec<[u8; ECDSA_PUBKEY_LEN]>, SignError>>()?;
        multisig_redeem_script_ecdsa(pubkeys.iter(), required).map_err(multisig_err_to_sign_err)
    } else {
        let pubkeys = psi
            .pub_key_signature_pairs
            .iter()
            .map(|pair| schnorr_serialized_pubkey_from_xpub(&pair.extended_pub_key))
            .collect::<Result<Vec<[u8; SCHNORR_PUBKEY_LEN]>, SignError>>()?;
        multisig_redeem_script(pubkeys.iter(), required).map_err(multisig_err_to_sign_err)
    }
}

fn schnorr_serialized_pubkey_from_xpub(xpub_str: &str) -> Result<[u8; SCHNORR_PUBKEY_LEN], SignError> {
    let xpub: ExtendedPublicKey<secp256k1::PublicKey> = xpub_str.parse()?;
    Ok(xpub.public_key().x_only_public_key().0.serialize())
}

fn ecdsa_serialized_pubkey_from_xpub(xpub_str: &str) -> Result<[u8; ECDSA_PUBKEY_LEN], SignError> {
    let xpub: ExtendedPublicKey<secp256k1::PublicKey> = xpub_str.parse()?;
    Ok(xpub.public_key().serialize())
}

fn script_builder_to_sign_err(err: kaspa_txscript::script_builder::ScriptBuilderError) -> SignError {
    SignError::Invalid { field: "signatureScript", reason: format!("script builder: {err}") }
}

fn multisig_err_to_sign_err(err: MultisigCreateError) -> SignError {
    SignError::Invalid { field: "multisigRedeemScript", reason: err.to_string() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::serialization::wire::{
        PartiallySignedInput, PartiallySignedTransaction, PubKeySignaturePair, ScriptPublicKey, SubnetworkId, TransactionInput,
        TransactionMessage, TransactionOutput,
    };

    /// Cosigner-level xpubs (testnet `ktub` version) sourced from
    /// `tests/fixtures/legacy_go_v1_multisig_2of3.json`. The fixture
    /// stores three cosigner-level extended public keys; these
    /// strings parse via `kaspa_bip32::ExtendedPublicKey` and have
    /// the proper structure for redeem-script construction.
    const COSIGNER_XPUB_1: &str =
        "ktub23t7RjF5AQHwkhCaiTAoTdzkgvXGAbfL8jPre2FhPzDXqVrEB3AkRmfxtLwbGAq46ShaGdsRToeKEcJUeuy17Vh8QmRgfdSqZJGBJREKP44";
    const COSIGNER_XPUB_2: &str =
        "ktub22TH54k6Nc3PMjGUfnzD2KkaV1CPu8rnALjjwC2BS2NWcUy4cW5JxpgUbzNAqEHmZ9bvzf3GBPVMeLYKiVfgsKbGXrU26MQJbmSgtyeqRzL";
    const COSIGNER_XPUB_3: &str =
        "ktub22g7fH7EEaGekCG4ZDLSTsbcJsPyYiFeSthPbB31Crwb8uxm5hWsZxtUqRsQHwmKvMKtZkRdJpfauWyLyGCiDQLX3vP7qY8A5joML18BTkx";

    /// 65-byte synthetic signature blob (64 zero sig bytes + 1
    /// sigHashType byte). Sign-flow correctness is tested by
    /// `super::tests`; here we only verify the combination layer's
    /// packing.
    fn synthetic_sig() -> Vec<u8> {
        let mut v = vec![0u8; 64];
        v.push(0x01);
        v
    }

    fn dummy_tx() -> TransactionMessage {
        TransactionMessage {
            version: 0,
            inputs: vec![TransactionInput {
                previous_outpoint: Some(crate::serialization::wire::Outpoint {
                    transaction_id: Some(crate::serialization::wire::TransactionId { bytes: vec![0u8; 32] }),
                    index: 0,
                }),
                signature_script: Vec::new(),
                sequence: 0,
                sig_op_count: 0,
            }],
            outputs: vec![TransactionOutput { value: 1, script_public_key: Some(ScriptPublicKey { version: 0, script: vec![0x51] }) }],
            lock_time: 0,
            subnetwork_id: Some(SubnetworkId { bytes: vec![0u8; 20] }),
            gas: 0,
            payload: Vec::new(),
        }
    }

    fn singlekey_psi_with_signature(signature: Vec<u8>) -> PartiallySignedInput {
        PartiallySignedInput {
            redeem_script: Vec::new(),
            prev_output: Some(TransactionOutput {
                value: 1_000,
                script_public_key: Some(ScriptPublicKey { version: 0, script: vec![0x51] }),
            }),
            minimum_signatures: 1,
            pub_key_signature_pairs: vec![PubKeySignaturePair { extended_pub_key: COSIGNER_XPUB_1.to_owned(), signature }],
            derivation_path: "m/0/0".to_owned(),
        }
    }

    fn multisig_2of3_psi_with_signatures(sig_1: Vec<u8>, sig_2: Vec<u8>, sig_3: Vec<u8>) -> PartiallySignedInput {
        PartiallySignedInput {
            redeem_script: Vec::new(),
            prev_output: Some(TransactionOutput {
                value: 1_000,
                script_public_key: Some(ScriptPublicKey { version: 0, script: vec![0x51] }),
            }),
            minimum_signatures: 2,
            pub_key_signature_pairs: vec![
                PubKeySignaturePair { extended_pub_key: COSIGNER_XPUB_1.to_owned(), signature: sig_1 },
                PubKeySignaturePair { extended_pub_key: COSIGNER_XPUB_2.to_owned(), signature: sig_2 },
                PubKeySignaturePair { extended_pub_key: COSIGNER_XPUB_3.to_owned(), signature: sig_3 },
            ],
            derivation_path: "m/0/0/0".to_owned(),
        }
    }

    #[test]
    fn test_extract_singlekey_pushes_signature_via_op_data_65() {
        let pst = PartiallySignedTransaction {
            tx: Some(dummy_tx()),
            partially_signed_inputs: vec![singlekey_psi_with_signature(synthetic_sig())],
        };
        let tx = extract_transaction(&pst, false).expect("extract succeeds");
        assert_eq!(tx.inputs.len(), 1);
        let sigscript = &tx.inputs[0].signature_script;
        // ScriptBuilder.AddData(65 bytes) emits OP_DATA_65 (0x41) + 65 bytes = 66 bytes total.
        assert_eq!(sigscript.len(), 66, "single-key sigscript = OP_DATA_65 + 65-byte sig blob");
        assert_eq!(sigscript[0], 0x41, "first opcode is OP_DATA_65 (0x41)");
        assert_eq!(sigscript[65], 0x01, "last byte is the sigHashType (SIG_HASH_ALL)");
        assert_eq!(tx.inputs[0].sig_op_count, 1);
    }

    #[test]
    fn test_extract_singlekey_rejects_missing_signature() {
        let pst = PartiallySignedTransaction {
            tx: Some(dummy_tx()),
            partially_signed_inputs: vec![singlekey_psi_with_signature(Vec::new())],
        };
        match extract_transaction(&pst, false) {
            Err(SignError::Invalid { field, .. }) => assert_eq!(field, "PubKeySignaturePair.signature"),
            other => panic!("expected SignError::Invalid for missing signature, got {other:?}"),
        }
    }

    #[test]
    fn test_extract_multisig_2of3_schnorr_packs_two_sigs_plus_redeem_script() {
        let pst = PartiallySignedTransaction {
            tx: Some(dummy_tx()),
            partially_signed_inputs: vec![multisig_2of3_psi_with_signatures(synthetic_sig(), Vec::new(), synthetic_sig())],
        };
        let tx = extract_transaction(&pst, false).expect("extract succeeds");
        let sigscript = &tx.inputs[0].signature_script;

        // Multisig sigscript shape: OP_DATA_65 + 65 sig_1 + OP_DATA_65
        // + 65 sig_3 + push(redeem_script). Redeem script for 2-of-3
        // Schnorr is: OP_2 + (OP_DATA_32 + 32 pubkey) * 3 + OP_3 +
        // OP_CHECKMULTISIG = 1 + 33*3 + 1 + 1 = 102 bytes. PUSHDATA
        // framing of a 102-byte payload uses OP_PUSHDATA1 (0x4c) + 1
        // length byte + 102 = 104 bytes total prefix. Final sigscript
        // length = 66 + 66 + 104 = 236 bytes.
        assert_eq!(sigscript[0], 0x41, "first opcode is OP_DATA_65 (sig_1)");
        assert_eq!(sigscript[65], 0x01, "sig_1 ends with sigHashType byte");
        assert_eq!(sigscript[66], 0x41, "second opcode is OP_DATA_65 (sig_3)");
        assert_eq!(sigscript[131], 0x01, "sig_3 ends with sigHashType byte");
        assert_eq!(sigscript[132], 0x4c, "third PUSHDATA is OP_PUSHDATA1 (0x4c)");
        assert_eq!(sigscript[133], 102, "redeem script length is 102 bytes");
        // First redeem-script byte is OP_2 (push minimum-signatures = 2).
        assert_eq!(sigscript[134], 0x52, "redeem script begins with OP_2");
        // Last redeem-script byte is OP_CHECKMULTISIG (Schnorr opcode 0xae).
        let last = sigscript[sigscript.len() - 1];
        assert_eq!(last, 0xae, "redeem script ends with OP_CHECKMULTISIG (Schnorr)");
        // Second-to-last is OP_3 (number of public keys).
        assert_eq!(sigscript[sigscript.len() - 2], 0x53, "redeem script byte before checkmultisig is OP_3");

        assert_eq!(sigscript.len(), 66 + 66 + 2 + 102);
        assert_eq!(tx.inputs[0].sig_op_count, 3);
    }

    #[test]
    fn test_extract_multisig_2of3_ecdsa_uses_ecdsa_opcode() {
        let pst = PartiallySignedTransaction {
            tx: Some(dummy_tx()),
            partially_signed_inputs: vec![multisig_2of3_psi_with_signatures(synthetic_sig(), synthetic_sig(), Vec::new())],
        };
        let tx = extract_transaction(&pst, true).expect("extract succeeds");
        let sigscript = &tx.inputs[0].signature_script;

        // ECDSA pubkeys are 33 bytes -> redeem script = 1 (OP_2) +
        // (OP_DATA_33 + 33 pubkey) * 3 + 1 (OP_3) + 1 (OP_CHECKMULTISIG_ECDSA) =
        // 1 + 34*3 + 2 = 105 bytes. OP_PUSHDATA1 framing: 0x4c + 1
        // len byte + 105 = 107.
        let last = sigscript[sigscript.len() - 1];
        // OP_CHECKMULTISIG_ECDSA opcode is 0xa9.
        assert_eq!(last, 0xa9, "ECDSA-mode redeem script ends with OP_CHECKMULTISIG_ECDSA");
        assert_eq!(sigscript.len(), 66 + 66 + 2 + 105);
    }

    #[test]
    fn test_extract_multisig_rejects_when_insufficient_signatures() {
        let pst = PartiallySignedTransaction {
            tx: Some(dummy_tx()),
            partially_signed_inputs: vec![multisig_2of3_psi_with_signatures(synthetic_sig(), Vec::new(), Vec::new())],
        };
        match extract_transaction(&pst, false) {
            Err(SignError::Invalid { field, reason }) => {
                assert_eq!(field, "PartiallySignedInput");
                assert!(reason.contains("missing"), "expected missing-signatures reason, got {reason}");
            }
            other => panic!("expected Invalid error, got {other:?}"),
        }
    }
}
