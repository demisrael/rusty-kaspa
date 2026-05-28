use crate::{
    hashing::{
        sighash::{SigHashReusedValuesUnsync, calc_ecdsa_signature_hash, calc_schnorr_signature_hash},
        sighash_type::{SIG_HASH_ALL, SigHashType},
    },
    mass::{ComputeBudget, SigopCount},
    tx::{ComputeCommit, SignableTransaction, VerifiableTransaction},
};
use itertools::Itertools;
use std::collections::BTreeMap;
use std::iter::once;
use thiserror::Error;

#[derive(Error, Debug, Clone)]
pub enum Error {
    #[error("{0}")]
    Message(String),

    #[error("Secp256k1 -> {0}")]
    Secp256k1Error(#[from] secp256k1::Error),

    #[error("The transaction is partially signed")]
    PartiallySigned,

    #[error("The transaction is fully signed")]
    FullySigned,
}

/// A wrapper enum that represents the transaction signed state. A transaction
/// contained by this enum can be either fully signed or partially signed.
pub enum Signed {
    Fully(SignableTransaction),
    Partially(SignableTransaction),
}

impl Signed {
    /// Returns the transaction if it is fully signed, otherwise returns an error
    pub fn fully_signed(self) -> std::result::Result<SignableTransaction, Error> {
        match self {
            Signed::Fully(tx) => Ok(tx),
            Signed::Partially(_) => Err(Error::PartiallySigned),
        }
    }

    /// Returns the transaction if it is fully signed, otherwise returns the
    /// transaction as an error `Err(tx)`.
    #[allow(clippy::result_large_err)]
    pub fn try_fully_signed(self) -> std::result::Result<SignableTransaction, SignableTransaction> {
        match self {
            Signed::Fully(tx) => Ok(tx),
            Signed::Partially(tx) => Err(tx),
        }
    }

    /// Returns the transaction if it is partially signed, otherwise fail with an error
    pub fn partially_signed(self) -> std::result::Result<SignableTransaction, Error> {
        match self {
            Signed::Fully(_) => Err(Error::FullySigned),
            Signed::Partially(tx) => Ok(tx),
        }
    }

    /// Returns the transaction if it is partially signed, otherwise returns the
    /// transaction as an error `Err(tx)`.
    #[allow(clippy::result_large_err)]
    pub fn try_partially_signed(self) -> std::result::Result<SignableTransaction, SignableTransaction> {
        match self {
            Signed::Fully(tx) => Err(tx),
            Signed::Partially(tx) => Ok(tx),
        }
    }

    /// Returns the transaction regardless of whether it is fully or partially signed
    pub fn unwrap(self) -> SignableTransaction {
        match self {
            Signed::Fully(tx) => tx,
            Signed::Partially(tx) => tx,
        }
    }
}

/// Sign a transaction using schnorr
pub fn sign(mut signable_tx: SignableTransaction, schnorr_key: secp256k1::Keypair) -> SignableTransaction {
    let input_mass = if ComputeCommit::version_expects_compute_budget_field(signable_tx.tx.version) {
        // Assumes grams per sigop = 1000 and 1 compute budget = 100 gram
        ComputeBudget(10).into()
    } else {
        SigopCount(1).into()
    };
    for i in 0..signable_tx.tx.inputs.len() {
        signable_tx.tx.inputs[i].compute_commit = input_mass;
    }

    let reused_values = SigHashReusedValuesUnsync::new();
    for i in 0..signable_tx.tx.inputs.len() {
        let sig_hash = calc_schnorr_signature_hash(&signable_tx.as_verifiable(), i, SIG_HASH_ALL, &reused_values);
        let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
        let sig: [u8; 64] = *schnorr_key.sign_schnorr(msg).as_ref();
        // This represents OP_DATA_65 <SIGNATURE+SIGHASH_TYPE> (since signature length is 64 bytes and SIGHASH_TYPE is one byte)
        signable_tx.tx.inputs[i].signature_script = std::iter::once(65u8).chain(sig).chain([SIG_HASH_ALL.to_u8()]).collect();
    }
    signable_tx
}

/// Sign a transaction using schnorr
pub fn sign_with_multiple(mut mutable_tx: SignableTransaction, privkeys: Vec<[u8; 32]>) -> SignableTransaction {
    let mut map = BTreeMap::new();
    for privkey in privkeys {
        let schnorr_key = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, &privkey).unwrap();
        map.insert(schnorr_key.public_key().serialize(), schnorr_key);
    }

    let input_mass = if ComputeCommit::version_expects_compute_budget_field(mutable_tx.tx.version) {
        // Assumes grams per sigop = 1000 and 1 compute budget = 100 gram
        ComputeBudget(10).into()
    } else {
        SigopCount(1).into()
    };
    for i in 0..mutable_tx.tx.inputs.len() {
        mutable_tx.tx.inputs[i].compute_commit = input_mass;
    }

    let reused_values = SigHashReusedValuesUnsync::new();
    for i in 0..mutable_tx.tx.inputs.len() {
        let script = mutable_tx.entries[i].as_ref().unwrap().script_public_key.script();
        if let Some(schnorr_key) = map.get(script) {
            let sig_hash = calc_schnorr_signature_hash(&mutable_tx.as_verifiable(), i, SIG_HASH_ALL, &reused_values);
            let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
            let sig: [u8; 64] = *schnorr_key.sign_schnorr(msg).as_ref();
            // This represents OP_DATA_65 <SIGNATURE+SIGHASH_TYPE> (since signature length is 64 bytes and SIGHASH_TYPE is one byte)
            mutable_tx.tx.inputs[i].signature_script = std::iter::once(65u8).chain(sig).chain([SIG_HASH_ALL.to_u8()]).collect();
        }
    }
    mutable_tx
}

/// Signing algorithm of a per-input key, selected by the P2PK script template
/// the input pays to, so each input is signed with the algorithm its
/// `OP_CHECKSIG` variant verifies.
enum SigningCurve {
    Schnorr,
    Ecdsa,
}

// P2PK script-template bytes. `kaspa-txscript` owns the canonical opcode
// constants but depends on this crate, so the opcodes the signer needs to
// rebuild a P2PK script are named locally here. Schnorr P2PK is
// `OP_DATA_32 <32-byte x-only pubkey> OP_CHECKSIG`; ECDSA P2PK is
// `OP_DATA_33 <33-byte compressed pubkey> OP_CHECKSIGECDSA`.
const OP_DATA_32: u8 = 0x20;
const OP_DATA_33: u8 = 0x21;
const OP_DATA_65: u8 = 0x41;
const OP_CHECK_SIG: u8 = 0xac;
const OP_CHECK_SIG_ECDSA: u8 = 0xab;

/// TODO (aspect) - merge this with `v1` fn above or refactor wallet core to use the script engine.
/// Sign each input whose P2PK script matches one of `privkeys`, dispatching
/// Schnorr or ECDSA per the script's `OP_CHECKSIG` variant. Returns
/// `Signed::Fully` only when every input was matched and signed; an unmatched
/// input (e.g. a cosigner key not held locally) yields `Signed::Partially`.
#[allow(clippy::result_large_err)]
pub fn sign_with_multiple_v2(mut mutable_tx: SignableTransaction, privkeys: &[[u8; 32]]) -> Signed {
    let mut map = BTreeMap::new();
    for privkey in privkeys {
        let keypair = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, privkey).unwrap();
        // Schnorr P2PK: OP_DATA_32 <32-byte x-only pubkey> OP_CHECKSIG
        let x_only_public_key = keypair.public_key().x_only_public_key().0;
        let schnorr_script = once(OP_DATA_32).chain(x_only_public_key.serialize()).chain(once(OP_CHECK_SIG)).collect_vec();
        map.insert(schnorr_script, (keypair, SigningCurve::Schnorr));
        // ECDSA P2PK: OP_DATA_33 <33-byte compressed pubkey> OP_CHECKSIGECDSA
        let ecdsa_script = once(OP_DATA_33).chain(keypair.public_key().serialize()).chain(once(OP_CHECK_SIG_ECDSA)).collect_vec();
        map.insert(ecdsa_script, (keypair, SigningCurve::Ecdsa));
    }

    let reused_values = SigHashReusedValuesUnsync::new();
    let mut additional_signatures_required = false;
    for i in 0..mutable_tx.tx.inputs.len() {
        let script = mutable_tx.entries[i].as_ref().unwrap().script_public_key.script();
        let Some((keypair, curve)) = map.get(script) else {
            additional_signatures_required = true;
            continue;
        };
        let sig: [u8; 64] = match curve {
            SigningCurve::Schnorr => {
                let sig_hash = calc_schnorr_signature_hash(&mutable_tx.as_verifiable(), i, SIG_HASH_ALL, &reused_values);
                let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
                *keypair.sign_schnorr(msg).as_ref()
            }
            SigningCurve::Ecdsa => {
                let sig_hash = calc_ecdsa_signature_hash(&mutable_tx.as_verifiable(), i, SIG_HASH_ALL, &reused_values);
                let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
                keypair.secret_key().sign_ecdsa(msg).serialize_compact()
            }
        };
        // This represents OP_DATA_65 <SIGNATURE+SIGHASH_TYPE> (since signature length is 64 bytes and SIGHASH_TYPE is one byte)
        mutable_tx.tx.inputs[i].signature_script = once(OP_DATA_65).chain(sig).chain([SIG_HASH_ALL.to_u8()]).collect();
    }
    if additional_signatures_required { Signed::Partially(mutable_tx) } else { Signed::Fully(mutable_tx) }
}

/// Sign a transaction input with a sighash_type using schnorr
pub fn sign_input(tx: &impl VerifiableTransaction, input_index: usize, private_key: &[u8; 32], hash_type: SigHashType) -> Vec<u8> {
    let reused_values = SigHashReusedValuesUnsync::new();

    let hash = calc_schnorr_signature_hash(tx, input_index, hash_type, &reused_values);
    let msg = secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).unwrap();
    let schnorr_key = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, private_key).unwrap();
    let sig: [u8; 64] = *schnorr_key.sign_schnorr(msg).as_ref();

    // This represents OP_DATA_65 <SIGNATURE+SIGHASH_TYPE> (since signature length is 64 bytes and SIGHASH_TYPE is one byte)
    std::iter::once(65u8).chain(sig).chain([hash_type.to_u8()]).collect()
}

pub fn verify(tx: &impl VerifiableTransaction) -> Result<(), Error> {
    let reused_values = SigHashReusedValuesUnsync::new();
    for (i, (input, entry)) in tx.populated_inputs().enumerate() {
        if input.signature_script.is_empty() {
            return Err(Error::Message(format!("Signature is empty for input: {i}")));
        }
        let pk = &entry.script_public_key.script()[1..33];
        let pk = secp256k1::XOnlyPublicKey::from_slice(pk)?;
        let sig = secp256k1::schnorr::Signature::from_slice(&input.signature_script[1..65])?;
        let sig_hash = calc_schnorr_signature_hash(tx, i, SIG_HASH_ALL, &reused_values);
        let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice())?;
        sig.verify(&msg, &pk)?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        config::params::MAINNET_PARAMS,
        mass::{ComputeBudget, GRAMS_PER_COMPUTE_BUDGET_UNIT, SigopCount},
        subnets::SubnetworkId,
        tx::*,
    };
    use secp256k1::{Secp256k1, rand};
    use std::str::FromStr;

    #[test]
    fn test_and_verify_sign() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let script_pub_key = ScriptVec::from_slice(&public_key.serialize());

        let (secret_key2, public_key2) = secp.generate_keypair(&mut rand::thread_rng());
        let script_pub_key2 = ScriptVec::from_slice(&public_key2.serialize());

        let prev_tx_id = TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();
        let unsigned_tx = Transaction::new(
            0,
            vec![
                TransactionInput {
                    previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                    signature_script: vec![],
                    sequence: 0,
                    compute_commit: SigopCount(0).into(),
                },
                TransactionInput {
                    previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 1 },
                    signature_script: vec![],
                    sequence: 1,
                    compute_commit: SigopCount(0).into(),
                },
                TransactionInput {
                    previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 2 },
                    signature_script: vec![],
                    sequence: 2,
                    compute_commit: SigopCount(0).into(),
                },
            ],
            vec![
                TransactionOutput { value: 300, script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()), covenant: None },
                TransactionOutput { value: 300, script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()), covenant: None },
            ],
            1615462089000,
            SubnetworkId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );

        let entries = vec![
            UtxoEntry {
                amount: 100,
                script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: None,
            },
            UtxoEntry {
                amount: 200,
                script_public_key: ScriptPublicKey::new(0, script_pub_key),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: None,
            },
            UtxoEntry {
                amount: 300,
                script_public_key: ScriptPublicKey::new(0, script_pub_key2),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: None,
            },
        ];
        let signed_tx = sign_with_multiple(
            SignableTransaction::with_entries(unsigned_tx, entries),
            vec![secret_key.secret_bytes(), secret_key2.secret_bytes()],
        );

        assert!(verify(&signed_tx.as_verifiable()).is_ok());
    }

    #[test]
    fn test_signers_assign_version_appropriate_input_mass() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let script_pub_key = ScriptVec::from_slice(&public_key.serialize());
        let prev_tx_id = TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();

        let build_unsigned_tx = |version| {
            Transaction::new(
                version,
                vec![TransactionInput {
                    previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: 0 },
                    signature_script: vec![],
                    sequence: 0,
                    compute_commit: SigopCount(0).into(),
                }],
                vec![TransactionOutput {
                    value: 100,
                    script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()),
                    covenant: None,
                }],
                0,
                SubnetworkId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
                0,
                vec![],
            )
        };
        let entry = UtxoEntry {
            amount: 100,
            script_public_key: ScriptPublicKey::new(0, script_pub_key.clone()),
            block_daa_score: 0,
            is_coinbase: false,
            covenant_id: None,
        };

        let signed_v0 = sign(
            SignableTransaction::with_entries(build_unsigned_tx(0), vec![entry.clone()]),
            secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key),
        );
        assert_eq!(signed_v0.tx.inputs[0].compute_commit, SigopCount(1).into());

        let signed_v1 = sign(
            SignableTransaction::with_entries(build_unsigned_tx(1), vec![entry.clone()]),
            secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key),
        );
        assert_eq!(
            signed_v1.tx.inputs[0].compute_commit,
            ComputeBudget(MAINNET_PARAMS.mass_per_sig_op.div_ceil(GRAMS_PER_COMPUTE_BUDGET_UNIT) as u16).into()
        );

        let signed_multi_v0 = sign_with_multiple(
            SignableTransaction::with_entries(build_unsigned_tx(0), vec![entry.clone()]),
            vec![secret_key.secret_bytes()],
        );
        assert_eq!(signed_multi_v0.tx.inputs[0].compute_commit, SigopCount(1).into());

        let signed_multi_v1 =
            sign_with_multiple(SignableTransaction::with_entries(build_unsigned_tx(1), vec![entry]), vec![secret_key.secret_bytes()]);
        assert_eq!(
            signed_multi_v1.tx.inputs[0].compute_commit,
            ComputeBudget(MAINNET_PARAMS.mass_per_sig_op.div_ceil(GRAMS_PER_COMPUTE_BUDGET_UNIT) as u16).into()
        );
    }

    /// Build a signable transaction with one input per supplied P2PK script,
    /// each spending a fresh UTXO carrying that script.
    fn signable_for_scripts(scripts: Vec<ScriptVec>) -> SignableTransaction {
        let prev_tx_id = TransactionId::from_str("880eb9819a31821d9d2399e2f35e2433b72637e393d71ecc9b8d0250f49153c3").unwrap();
        let inputs = (0..scripts.len())
            .map(|i| TransactionInput {
                previous_outpoint: TransactionOutpoint { transaction_id: prev_tx_id, index: i as u32 },
                signature_script: vec![],
                sequence: i as u64,
                compute_commit: SigopCount(0).into(),
            })
            .collect();
        let unsigned_tx = Transaction::new(
            0,
            inputs,
            vec![TransactionOutput {
                value: 100,
                script_public_key: ScriptPublicKey::new(0, ScriptVec::from_slice(&[OP_CHECK_SIG])),
                covenant: None,
            }],
            1615462089000,
            SubnetworkId::from_bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]),
            0,
            vec![],
        );
        let entries = scripts
            .into_iter()
            .map(|script| UtxoEntry {
                amount: 1000,
                script_public_key: ScriptPublicKey::new(0, script),
                block_daa_score: 0,
                is_coinbase: false,
                covenant_id: None,
            })
            .collect();
        SignableTransaction::with_entries(unsigned_tx, entries)
    }

    /// Regression for the ECDSA single-sig send path: `sign_with_multiple_v2`
    /// must fully sign an `OP_CHECKSIGECDSA` P2PK input and emit a signature
    /// the ECDSA consensus rules accept. Before dual-curve dispatch the
    /// per-key lookup map held only the Schnorr P2PK script form, so an ECDSA
    /// input never matched and the transaction came back partially signed
    /// (the `The transaction is partially signed` failure observed on a
    /// funded ECDSA single-sig send).
    #[test]
    fn sign_with_multiple_v2_signs_ecdsa_single_sig_input() {
        let secp = Secp256k1::new();
        let (secret_key, public_key) = secp.generate_keypair(&mut rand::thread_rng());
        let script: Vec<u8> =
            std::iter::once(OP_DATA_33).chain(public_key.serialize()).chain(std::iter::once(OP_CHECK_SIG_ECDSA)).collect();
        let signable = signable_for_scripts(vec![ScriptVec::from_slice(&script)]);

        let signed = match sign_with_multiple_v2(signable, &[secret_key.secret_bytes()]) {
            Signed::Fully(tx) => tx,
            Signed::Partially(_) => panic!("ECDSA single-sig input must be fully signed, not partially"),
        };

        let sig_script = &signed.tx.inputs[0].signature_script;
        assert_eq!(sig_script.len(), 66, "OP_DATA_65 push opcode + 64-byte signature + 1 sighash-type byte");
        assert_eq!(sig_script[0], OP_DATA_65);
        assert_eq!(*sig_script.last().unwrap(), SIG_HASH_ALL.to_u8());

        let reused_values = SigHashReusedValuesUnsync::new();
        let sig_hash = calc_ecdsa_signature_hash(&signed.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
        let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).unwrap();
        let sig = secp256k1::ecdsa::Signature::from_compact(&sig_script[1..65]).unwrap();
        secp.verify_ecdsa(&msg, &sig, &public_key).expect("emitted ECDSA signature must verify against the spending pubkey");
    }

    /// `sign_with_multiple_v2` dispatches per input: a Schnorr P2PK input and
    /// an ECDSA P2PK input in the same transaction are each signed with the
    /// matching algorithm, and both signatures verify. Locks Schnorr behavior
    /// unchanged while ECDSA support is added.
    #[test]
    fn sign_with_multiple_v2_dispatches_schnorr_and_ecdsa_per_input() {
        let secp = Secp256k1::new();
        let (schnorr_sk, schnorr_pk) = secp.generate_keypair(&mut rand::thread_rng());
        let (ecdsa_sk, ecdsa_pk) = secp.generate_keypair(&mut rand::thread_rng());

        let schnorr_x_only = schnorr_pk.x_only_public_key().0;
        let schnorr_script: Vec<u8> =
            std::iter::once(OP_DATA_32).chain(schnorr_x_only.serialize()).chain(std::iter::once(OP_CHECK_SIG)).collect();
        let ecdsa_script: Vec<u8> =
            std::iter::once(OP_DATA_33).chain(ecdsa_pk.serialize()).chain(std::iter::once(OP_CHECK_SIG_ECDSA)).collect();
        let signable = signable_for_scripts(vec![ScriptVec::from_slice(&schnorr_script), ScriptVec::from_slice(&ecdsa_script)]);

        let signed = match sign_with_multiple_v2(signable, &[schnorr_sk.secret_bytes(), ecdsa_sk.secret_bytes()]) {
            Signed::Fully(tx) => tx,
            Signed::Partially(_) => panic!("both single-sig inputs must be fully signed, not partially"),
        };

        let reused_values = SigHashReusedValuesUnsync::new();

        // Input 0 pays to a Schnorr P2PK script and must verify under Schnorr.
        let schnorr_hash = calc_schnorr_signature_hash(&signed.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
        let schnorr_msg = secp256k1::Message::from_digest_slice(schnorr_hash.as_bytes().as_slice()).unwrap();
        let schnorr_sig = secp256k1::schnorr::Signature::from_slice(&signed.tx.inputs[0].signature_script[1..65]).unwrap();
        schnorr_sig.verify(&schnorr_msg, &schnorr_x_only).expect("Schnorr input signature must verify");

        // Input 1 pays to an ECDSA P2PK script and must verify under ECDSA.
        let ecdsa_hash = calc_ecdsa_signature_hash(&signed.as_verifiable(), 1, SIG_HASH_ALL, &reused_values);
        let ecdsa_msg = secp256k1::Message::from_digest_slice(ecdsa_hash.as_bytes().as_slice()).unwrap();
        let ecdsa_sig = secp256k1::ecdsa::Signature::from_compact(&signed.tx.inputs[1].signature_script[1..65]).unwrap();
        secp.verify_ecdsa(&ecdsa_msg, &ecdsa_sig, &ecdsa_pk).expect("ECDSA input signature must verify");
    }
}
