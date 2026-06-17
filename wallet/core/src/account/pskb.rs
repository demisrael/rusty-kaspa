//!
//! Tools for interfacing wallet accounts with PSKBs.
//! (Partial Signed Kaspa Transaction Bundles).
//!

pub use crate::error::Error;
use crate::imports::*;
use crate::tx::PaymentOutput;
use crate::tx::PaymentOutputs;
use futures::stream;
use kaspa_bip32::{DerivationPath, KeyFingerprint, PrivateKey};
use kaspa_consensus_client::UtxoEntry as ClientUTXO;
use kaspa_consensus_core::hashing::sighash::{SigHashReusedValuesUnsync, calc_ecdsa_signature_hash, calc_schnorr_signature_hash};
use kaspa_consensus_core::tx::VerifiableTransaction;
use kaspa_consensus_core::tx::{TransactionInput, UtxoEntry};
use kaspa_txscript::MAX_PUB_KEYS_PER_MUTLTISIG;
use kaspa_txscript::extract_script_pub_key_address;
use kaspa_txscript::opcodes::codes::{Op1, Op16, OpCheckMultiSig, OpCheckMultiSigECDSA, OpData1, OpData32, OpData33, OpData65};
use kaspa_txscript::script_builder::ScriptBuilder;
use kaspa_wallet_core::tx::{Generator, GeneratorSettings, PaymentDestination, PendingTransaction};
pub use kaspa_wallet_pskt::bundle::Bundle;
use kaspa_wallet_pskt::bundle::{script_sig_to_address, unlock_utxo_outputs_as_batch_transaction_pskb};
use kaspa_wallet_pskt::prelude::KeySource;
use kaspa_wallet_pskt::prelude::lock_script_sig_templating_bytes;
use kaspa_wallet_pskt::prelude::{Finalizer, Inner, SignInputOk, Signature, Signer};
pub use kaspa_wallet_pskt::pskt::{Creator, PSKT};
use secp256k1::constants::{PUBLIC_KEY_SIZE, SCHNORR_PUBLIC_KEY_SIZE, SECRET_KEY_SIZE};
use secp256k1::ecdsa;
use secp256k1::schnorr;
use secp256k1::{Message, PublicKey};
use std::iter;

struct PSKBSignerInner {
    keydata: PrvKeyData,
    account: Arc<dyn Account>,
    payment_secret: Option<Secret>,
    keys: Mutex<AHashMap<Address, [u8; SECRET_KEY_SIZE]>>,
}

pub struct PSKBSigner {
    inner: Arc<PSKBSignerInner>,
}

impl PSKBSigner {
    pub fn new(account: Arc<dyn Account>, keydata: PrvKeyData, payment_secret: Option<Secret>) -> Self {
        Self { inner: Arc::new(PSKBSignerInner { keydata, account, payment_secret, keys: Mutex::new(AHashMap::new()) }) }
    }

    pub fn ingest(&self, addresses: &[Address]) -> Result<()> {
        let mut keys = self.inner.keys.lock()?;

        // Skip addresses that are already present in the key map.
        let addresses = addresses.iter().filter(|a| !keys.contains_key(a)).collect::<Vec<_>>();
        if !addresses.is_empty() {
            // let account = self.inner.account.clone().as_derivation_capable().expect("expecting derivation capable account");
            // let (receive, change) = account.derivation().addresses_indexes(&addresses)?;
            // let private_keys = account.create_private_keys(&self.inner.keydata, &self.inner.payment_secret, &receive, &change)?;
            let private_keys = self.inner.account.clone().create_address_private_keys(
                &self.inner.keydata,
                &self.inner.payment_secret,
                addresses.as_slice(),
            )?;
            for (address, private_key) in private_keys {
                keys.insert(address.clone(), private_key.to_bytes());
            }
        }
        Ok(())
    }

    fn public_key(&self, for_address: &Address) -> Result<PublicKey> {
        let keys = self.inner.keys.lock()?;
        match keys.get(for_address) {
            Some(private_key) => {
                let kp = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, private_key)?;
                Ok(kp.public_key())
            }
            None => Err(Error::from("PSKBSigner address coverage error")),
        }
    }

    fn sign_schnorr(&self, for_address: &Address, message: Message) -> Result<schnorr::Signature> {
        let keys = self.inner.keys.lock()?;
        match keys.get(for_address) {
            Some(private_key) => {
                let schnorr_key = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, private_key)?;
                Ok(schnorr_key.sign_schnorr(message))
            }
            None => Err(Error::from("PSKBSigner address coverage error")),
        }
    }

    /// Sign `message` for the cosigner whose receive/change address is
    /// `for_address`, using ECDSA. `SecretKey::sign_ecdsa` derives its
    /// nonce per RFC 6979 (deterministic); calling this method twice with
    /// the same `(private_key, message)` returns byte-identical
    /// signatures. The deterministic property is what enables cross-binary
    /// handoff parity (two binaries signing the same `(privkey, sighash)`
    /// pair produce byte-equal sigscripts).
    fn sign_ecdsa(&self, for_address: &Address, message: Message) -> Result<ecdsa::Signature> {
        let keys = self.inner.keys.lock()?;
        match keys.get(for_address) {
            Some(private_key) => {
                let secret_key = secp256k1::SecretKey::from_slice(private_key)?;
                Ok(secret_key.sign_ecdsa(message))
            }
            None => Err(Error::from("PSKBSigner address coverage error")),
        }
    }
}

pub struct PSKTGenerator {
    generator: Generator,
    signer: Arc<PSKBSigner>,
    prefix: Prefix,
}

impl PSKTGenerator {
    pub fn new(generator: Generator, signer: Arc<PSKBSigner>, prefix: Prefix) -> Self {
        Self { generator, signer, prefix }
    }

    pub fn stream(&self) -> impl Stream<Item = Result<PSKT<Signer>, Error>> {
        PSKTStream::new(self.generator.clone(), self.signer.clone(), self.prefix)
    }
}

struct PSKTStream {
    generator_stream: Pin<Box<dyn Stream<Item = Result<PendingTransaction, Error>> + Send>>,
    signer: Arc<PSKBSigner>,
    prefix: Prefix,
}

impl PSKTStream {
    fn new(generator: Generator, signer: Arc<PSKBSigner>, prefix: Prefix) -> Self {
        let generator_stream = generator.stream().map_err(Error::from);
        Self { generator_stream: Box::pin(generator_stream), signer, prefix }
    }
}

impl Stream for PSKTStream {
    type Item = Result<PSKT<Signer>, Error>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.as_ref();

        let _prefix = this.prefix;
        let _signer = this.signer.clone();

        match self.get_mut().generator_stream.as_mut().poll_next(cx) {
            Poll::Ready(Some(Ok(pending_tx))) => {
                let pskt = convert_pending_tx_to_pskt(pending_tx);
                Poll::Ready(Some(pskt))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

fn convert_pending_tx_to_pskt(pending_tx: PendingTransaction) -> Result<PSKT<Signer>, Error> {
    let signable_tx = pending_tx.signable_transaction();
    let verifiable_tx = signable_tx.as_verifiable();
    let populated_inputs: Vec<(&TransactionInput, &UtxoEntry)> = verifiable_tx.populated_inputs().collect();
    let pskt_inner = Inner::try_from((pending_tx.transaction(), populated_inputs.to_owned()))?;
    Ok(PSKT::<Signer>::from(pskt_inner))
}

pub async fn bundle_from_pskt_generator(generator: PSKTGenerator) -> Result<Bundle, Error> {
    let mut bundle: Bundle = Bundle::new();
    let mut stream = generator.stream();

    while let Some(pskt_result) = stream.next().await {
        match pskt_result {
            Ok(pskt) => bundle.add_pskt(pskt),
            Err(e) => return Err(e),
        }
    }

    Ok(bundle)
}
pub async fn pskb_signer_for_address(
    bundle: &Bundle,
    signer: Arc<PSKBSigner>,
    network_id: NetworkId,
    sign_for_address: Option<&Address>,
    derivation_path: Option<DerivationPath>,
    key_fingerprint: Option<KeyFingerprint>,
) -> Result<Bundle, Error> {
    let mut signed_bundle = Bundle::new();

    // If sign_for_address is provided, we'll use it for all signatures
    // Otherwise, collect addresses per PSKT
    let addresses_per_pskt: Vec<Vec<Address>> = if sign_for_address.is_some() {
        // Create a vec of single-address vecs
        bundle.iter().map(|_| vec![sign_for_address.unwrap().clone()]).collect()
    } else {
        // Collect addresses for each PSKT separately
        bundle
            .iter()
            .map(|inner| {
                inner
                    .inputs
                    .iter()
                    .filter_map(|input| input.utxo_entry.as_ref())
                    .filter_map(|utxo_entry| {
                        extract_script_pub_key_address(&utxo_entry.script_public_key.clone(), network_id.into()).ok()
                    })
                    .collect()
            })
            .collect()
    };

    // Prepare the signer with all unique addresses
    let all_addresses: Vec<Address> = addresses_per_pskt.iter().flat_map(|addresses| addresses.iter().cloned()).collect();
    signer.ingest(all_addresses.as_slice())?;

    // in case of keypair account, we don't have a derivation path,
    // so we need to skip the key source
    let mut key_source = None;
    if let Some(key_fingerprint) = key_fingerprint
        && let Some(derivation_path) = derivation_path
    {
        key_source = Some(KeySource { key_fingerprint, derivation_path: derivation_path.clone() });
    }

    // Per-account curve selection: ECDSA-bearing accounts (`account.ecdsa()`
    // returns `true`) sign with `calc_ecdsa_signature_hash` +
    // `signer.sign_ecdsa(..)` and wrap as `Signature::ECDSA(..)`; all other
    // accounts use the original Schnorr path. The branch is per-account
    // (constant across every input of every PSKT in this bundle) so the
    // dispatch cost is one boolean read per PSKT.
    let ecdsa = signer.inner.account.ecdsa();

    // Process each PSKT in the bundle
    for (pskt_idx, pskt_inner) in bundle.iter().cloned().enumerate() {
        let pskt: PSKT<Signer> = PSKT::from(pskt_inner);
        let current_addresses = &addresses_per_pskt[pskt_idx];

        // Create new reused values for each PSKT
        let reused_values = SigHashReusedValuesUnsync::new();

        let sign = |signer_pskt: PSKT<Signer>| -> Result<PSKT<Signer>, Error> {
            signer_pskt
                .pass_signature_sync(|tx, sighash| -> Result<Vec<SignInputOk>, String> {
                    tx.tx
                        .inputs
                        .iter()
                        .enumerate()
                        .map(|(input_idx, _input)| {
                            // Get the appropriate address for this input
                            let address = if let Some(sign_addr) = sign_for_address {
                                sign_addr
                            } else {
                                current_addresses.get(input_idx).ok_or_else(|| format!("No address found for input {}", input_idx))?
                            };

                            let pub_key = signer.public_key(address).map_err(|e| format!("Failed to get public key: {}", e))?;

                            let signature = if ecdsa {
                                let hash =
                                    calc_ecdsa_signature_hash(&tx.as_verifiable(), input_idx, sighash[input_idx], &reused_values);
                                let msg =
                                    secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|e| e.to_string())?;
                                let sig = signer.sign_ecdsa(address, msg).map_err(|e| format!("Failed to sign: {}", e))?;
                                Signature::ECDSA(sig)
                            } else {
                                let hash =
                                    calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, sighash[input_idx], &reused_values);
                                let msg =
                                    secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|e| e.to_string())?;
                                let sig = signer.sign_schnorr(address, msg).map_err(|e| format!("Failed to sign: {}", e))?;
                                Signature::Schnorr(sig)
                            };

                            Ok(SignInputOk { signature, pub_key, key_source: key_source.clone() })
                        })
                        .collect()
                })
                .map_err(Error::from)
        };

        let signed_pskt = sign(pskt)?;
        signed_bundle.add_pskt(signed_pskt);
    }

    Ok(signed_bundle)
}

/// Decode a multisig script integer (K or N) at the start of `bytes`.
///
/// `ScriptBuilder::add_i64` emits 1..16 as a single small-int opcode
/// (`Op1..Op16`) and emits 17..127 as a one-byte PUSHDATA (`OpData1`
/// followed by the value as an unsigned byte with the sign bit unset).
/// The consensus `OpCheckMultiSig` walk reads either form. Values above
/// `MAX_PUB_KEYS_PER_MUTLTISIG` exceed the consensus stack-pubkey-count
/// cap and are refused as parse errors so a downstream caller never
/// processes a K or N the script engine itself would reject. Returns
/// the decoded value and the number of bytes consumed from `bytes`.
fn decode_multisig_script_int(bytes: &[u8]) -> Result<(usize, usize), Error> {
    // High bit of a one-byte txscript integer = sign bit (per
    // `crypto/txscript/src/data_stack.rs::serialize_i64`). A positive K/N
    // value below the consensus cap MUST clear this bit; anything with it
    // set is a negative encoding and is rejected before the cap check.
    const TXSCRIPT_SIGN_BIT: u8 = 0x80;

    if bytes.is_empty() {
        return Err(Error::custom("multisig script integer expected but bytes empty"));
    }
    let first = bytes[0];
    if (Op1..=Op16).contains(&first) {
        return Ok((((first - Op1) + 1) as usize, 1));
    }
    if first == OpData1 {
        if bytes.len() < 2 {
            return Err(Error::custom("OpData1 multisig script integer missing value byte"));
        }
        let val = bytes[1];
        if val & TXSCRIPT_SIGN_BIT != 0 {
            return Err(Error::custom(format!("multisig script integer 0x{val:02x} has sign bit set; not a positive K/N value")));
        }
        if (val as i32) > MAX_PUB_KEYS_PER_MUTLTISIG {
            return Err(Error::custom(format!(
                "multisig script integer {val} exceeds the consensus stack-pubkey-count cap {MAX_PUB_KEYS_PER_MUTLTISIG}"
            )));
        }
        return Ok((val as usize, 2));
    }
    Err(Error::custom(format!("expected multisig script integer (Op1..Op16 or OpData1), got 0x{first:02x}")))
}

/// Parse a multisig redeem script and extract pubkey PUSHDATAs in source order.
///
/// Expected layout: `K <pubkey-pushdata>{N} N OpCheckMultiSig[ECDSA]`.
/// `K` and `N` are encoded as script integers up to the consensus cap
/// `MAX_PUB_KEYS_PER_MUTLTISIG` -- 1..16 inclusive as the small-int opcode
/// `Op1..Op16` and 17..20 as a one-byte PUSHDATA (`OpData1` + value byte),
/// matching what `ScriptBuilder::add_i64` emits. Each pubkey pushdata is
/// `OpData32` + 32 bytes for Schnorr x-only keys, or `OpData33` + 33 bytes
/// for ECDSA compressed keys. The returned pubkey-bytes vectors preserve
/// the redeem-script's order, which is the order `OpCheckMultiSig` walks
/// at consensus time.
fn parse_redeem_script_pubkeys(redeem_script: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    if redeem_script.len() < 3 {
        return Err(Error::custom("redeem script too short to be a multisig script"));
    }

    let (_k, k_consumed) = decode_multisig_script_int(redeem_script)?;
    let mut i = k_consumed;

    let mut pubkeys = Vec::new();

    while i < redeem_script.len() {
        let op = redeem_script[i];
        match op {
            op if op == OpData32 => {
                i += 1;
                if i + SCHNORR_PUBLIC_KEY_SIZE > redeem_script.len() {
                    return Err(Error::custom("truncated OpData32 pubkey pushdata in redeem script"));
                }
                pubkeys.push(redeem_script[i..i + SCHNORR_PUBLIC_KEY_SIZE].to_vec());
                i += SCHNORR_PUBLIC_KEY_SIZE;
            }
            op if op == OpData33 => {
                i += 1;
                if i + PUBLIC_KEY_SIZE > redeem_script.len() {
                    return Err(Error::custom("truncated OpData33 pubkey pushdata in redeem script"));
                }
                pubkeys.push(redeem_script[i..i + PUBLIC_KEY_SIZE].to_vec());
                i += PUBLIC_KEY_SIZE;
            }
            _ => {
                let (trailer_n, n_consumed) = decode_multisig_script_int(&redeem_script[i..])?;
                if i + n_consumed >= redeem_script.len() {
                    return Err(Error::custom("redeem script trailer missing OpCheckMultiSig opcode"));
                }
                let trailer = redeem_script[i + n_consumed];
                if trailer != OpCheckMultiSig && trailer != OpCheckMultiSigECDSA {
                    return Err(Error::custom(format!(
                        "redeem script trailer expected OpCheckMultiSig (0x{:02x}) or OpCheckMultiSigECDSA (0x{:02x}), got 0x{:02x}",
                        OpCheckMultiSig, OpCheckMultiSigECDSA, trailer
                    )));
                }
                if trailer_n != pubkeys.len() {
                    return Err(Error::custom(format!(
                        "redeem script trailer N={trailer_n} does not match the {} pubkey pushdatas parsed",
                        pubkeys.len()
                    )));
                }
                if i + n_consumed + 1 != redeem_script.len() {
                    return Err(Error::custom(format!(
                        "redeem script has {} trailing bytes after OpCheckMultiSig",
                        redeem_script.len() - (i + n_consumed + 1)
                    )));
                }
                return Ok(pubkeys);
            }
        }
    }

    Err(Error::custom("redeem script ended without OP_N OpCheckMultiSig trailer"))
}

/// Per-cosigner Schnorr signing primitive for multi-signature accounts.
///
/// **Per-input path attribution.** For every input that carries a non-empty
/// `bip32_derivations` map, the helper derives this cosigner's signing key
/// from the recorded `KeySource.derivation_path`. The same input may sit at
/// any cosigner-prefix family on chain; the input-level path is the only
/// load-bearing handle to which family is being spent. Each cosigner derives
/// their local xprv at the per-input path, produces a pubkey, and signs the
/// matching redeem-script slot -- regardless of which cosigner's family was
/// funded.
///
/// **Backward-compatible fallback.** If an input's `bip32_derivations` map
/// is empty (e.g., a synthetic PSKT primitive test fixture or a PSKT that
/// predates per-input attribution), the helper falls back to the
/// `default_cosigner_index` argument applied as a single child step on this
/// cosigner's xprv at the `(address_type, address_index)` recovered from
/// the input's UTXO address via the family-aware lookup. Callers in the
/// current chain (`MultiSig::pskb_sign` and `build_multisig_signed_bundle`)
/// always pre-populate `bip32_derivations` via
/// `populate_multisig_redeem_scripts`, so the fallback only exercises the
/// primitive test path.
///
/// The returned bundle clones every PSKT from `bundle` and populates each
/// input's `partial_sigs` with this cosigner's Schnorr signature keyed by
/// the derived pubkey.
pub async fn pskb_signer_for_multisig_cosigner(
    bundle: &Bundle,
    account: Arc<dyn Account>,
    prv_key_data: &PrvKeyData,
    payment_secret: Option<&Secret>,
    default_cosigner_index: u32,
    network_id: NetworkId,
) -> Result<Bundle, Error> {
    let payload = prv_key_data.payload.decrypt(payment_secret)?;
    let xkey = payload.get_xprv(payment_secret)?;

    let derivation_capable = account.clone().as_derivation_capable()?;
    let derivation = derivation_capable.derivation();

    // Per-account curve selection: ECDSA-bearing multisig accounts
    // (`account.ecdsa()` returns `true`) sign with
    // `calc_ecdsa_signature_hash` + `secret_key.sign_ecdsa(msg)` and wrap
    // as `Signature::ECDSA(..)`. Schnorr-bearing accounts retain the
    // original `keypair.sign_schnorr(msg)` path. The dispatch cost is one
    // boolean read for the whole bundle.
    let ecdsa = account.ecdsa();

    let mut signed_bundle = Bundle::new();

    for pskt_inner in bundle.iter().cloned() {
        let pskt: PSKT<Signer> = PSKT::from(pskt_inner.clone());

        // Resolve per-input signing key once per PSKT. The vector index matches
        // the input position so the signing closure (which only receives the
        // input index) can look up the pre-derived keypair without re-running
        // the per-input derivation walk inside the signing critical section.
        // Each entry also carries the pre-existing `bip32_derivations`
        // KeySource for the signing pubkey (when the input was originated
        // with per-input derivation attribution); the signing closure echoes
        // it back via `SignInputOk.key_source` so `pass_signature_sync`'s
        // `bip32_derivations.insert(pub_key, key_source)` step is idempotent
        // across the multi-cosigner accumulate loop. Without the echo, an
        // operator-Send signer running once per local seed overwrites the
        // pre-populated KeySource with `None`, and the per-cosigner bundles
        // fail to combine on `bip32_derivations` conflict at accumulate.
        type InputKey = (secp256k1::SecretKey, secp256k1::PublicKey, Option<kaspa_wallet_pskt::prelude::KeySource>);
        let mut input_keys: Vec<InputKey> = Vec::with_capacity(pskt_inner.inputs.len());
        // The requested cosigner position selects WHICH recorded attribution
        // entry to sign with: one key can back several cosigner positions
        // (several of its hardened children registered in one group), and
        // every such entry's path is derivable from the same xprv, so
        // matching by derivability alone would always re-sign the first
        // entry. The position's xpub fingerprint pins the entry.
        let position_fingerprint =
            account.xpub_keys().and_then(|xpubs| xpubs.get(default_cosigner_index as usize)).map(|xpub| xpub.fingerprint());
        for (input_idx, input) in pskt_inner.inputs.iter().enumerate() {
            let mut derived_from_key_source = None;
            for (recorded_pubkey, key_source) in input.bip32_derivations.iter() {
                let Some(key_source) = key_source else {
                    continue;
                };
                if let Some(expected_fingerprint) = position_fingerprint
                    && key_source.key_fingerprint != expected_fingerprint
                {
                    continue;
                }
                let mut current = xkey.clone();
                for child in key_source.derivation_path.as_ref() {
                    current = current.derive_child(*child)?;
                }
                let secret_key = *current.private_key();
                let keypair = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, secret_key.as_ref())?;
                let pub_key = keypair.public_key();
                if pub_key == *recorded_pubkey {
                    derived_from_key_source = Some((secret_key, pub_key, Some(key_source.clone())));
                    break;
                }
            }

            let (secret_key, pub_key, existing_key_source) = if let Some(input_key) = derived_from_key_source {
                input_key
            } else {
                // Fallback: build the receive/change vectors from the input's
                // UTXO address and derive a single key using the
                // default_cosigner_index. Preserves the cycle-1 primitive
                // test path.
                use crate::account::variants::multisig::MULTISIG_ACCOUNT_KIND;
                let utxo_entry =
                    input.utxo_entry.as_ref().ok_or_else(|| Error::custom(format!("No utxo_entry for input {input_idx}")))?;
                let address = extract_script_pub_key_address(&utxo_entry.script_public_key, network_id.into())?;
                let (receive, change) = derivation.addresses_indexes(&[&address])?;
                let fallback_account_index = account
                    .xpub_keys()
                    .and_then(|xpubs| xpubs.get(default_cosigner_index as usize))
                    .map(|xpub| xpub.attrs().child_number.index() as u64)
                    .unwrap_or_else(|| derivation_capable.account_index());
                let private_keys = crate::account::create_private_keys(
                    &MULTISIG_ACCOUNT_KIND.into(),
                    default_cosigner_index,
                    fallback_account_index,
                    &xkey,
                    &receive,
                    &change,
                )?;
                let secret_key = private_keys
                    .into_iter()
                    .next()
                    .map(|(_, sk)| sk)
                    .ok_or_else(|| Error::custom(format!("No private key derived for input {input_idx}")))?;
                let keypair = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, secret_key.as_ref())?;
                (secret_key, keypair.public_key(), None)
            };

            if input.partial_sigs.contains_key(&pub_key) {
                return Err(Error::MultisigDuplicateCosignerSignature { cosigner_index: default_cosigner_index, pub_key });
            }
            input_keys.push((secret_key, pub_key, existing_key_source));
        }

        let reused_values = SigHashReusedValuesUnsync::new();

        let signed_pskt = pskt
            .pass_signature_sync(|tx, sighash| -> Result<Vec<SignInputOk>, String> {
                tx.tx
                    .inputs
                    .iter()
                    .enumerate()
                    .map(|(input_idx, _input)| {
                        let (secret_key, pub_key, key_source) =
                            input_keys.get(input_idx).ok_or_else(|| format!("No signing key prepared for input {input_idx}"))?;
                        let signature = if ecdsa {
                            let hash = calc_ecdsa_signature_hash(&tx.as_verifiable(), input_idx, sighash[input_idx], &reused_values);
                            let msg = secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|e| e.to_string())?;
                            Signature::ECDSA(secret_key.sign_ecdsa(msg))
                        } else {
                            let keypair = secp256k1::Keypair::from_seckey_slice(secp256k1::SECP256K1, secret_key.as_ref())
                                .map_err(|e| e.to_string())?;
                            let hash = calc_schnorr_signature_hash(&tx.as_verifiable(), input_idx, sighash[input_idx], &reused_values);
                            let msg = secp256k1::Message::from_digest_slice(hash.as_bytes().as_slice()).map_err(|e| e.to_string())?;
                            Signature::Schnorr(keypair.sign_schnorr(msg))
                        };
                        Ok(SignInputOk { signature, pub_key: *pub_key, key_source: key_source.clone() })
                    })
                    .collect()
            })
            .map_err(Error::from)?;

        signed_bundle.add_pskt(signed_pskt);
    }

    Ok(signed_bundle)
}

pub fn finalize_pskt_one_or_more_sig_and_redeem_script(pskt: PSKT<Finalizer>) -> Result<PSKT<Finalizer>, Error> {
    // A multisig `script_sig` carries exactly the threshold number of
    // signatures by construction: the emission below collates one signature
    // per redeem-script slot up to the threshold. An input that presents more
    // partial signatures than its redeem-script threshold is therefore
    // malformed for collation and is declined before emission. This applies
    // only to multisig redeem scripts (`OP_M <pubkeys> OP_N OpCheckMultiSig`);
    // a non-multisig redeem script (e.g. a commit-reveal envelope) carries no
    // threshold and is left untouched.
    for (input_index, input) in pskt.inputs.iter().enumerate() {
        if let Some(redeem_script) = input.redeem_script.as_ref()
            && parse_redeem_script_pubkeys(redeem_script.as_slice()).is_ok()
        {
            let (threshold, _) = decode_multisig_script_int(redeem_script.as_slice())?;
            if input.partial_sigs.len() > threshold {
                return Err(Error::FinalizerExcessSignatures {
                    found: input.partial_sigs.len(),
                    allowed: threshold as u16,
                    input_index,
                });
            }
        }
    }

    let result = pskt.finalize_sync(|inner: &Inner| -> Result<Vec<Vec<u8>>, String> {
        inner
            .inputs
            .iter()
            .map(|input| -> Result<Vec<u8>, String> {
                let signatures: Vec<u8> = match input.redeem_script.as_ref() {
                    Some(redeem_script) => {
                        // Emit signatures in redeem-script pubkey order, not `partial_sigs`
                        // BTreeMap iteration order. The redeem-script's pubkey order is what
                        // `OpCheckMultiSig` walks forward at consensus time; misordered
                        // signatures cause irreversible pubkey-iter consumption and
                        // `failed -> NullFail` rejection.
                        let pubkeys =
                            parse_redeem_script_pubkeys(redeem_script.as_slice()).map_err(|e| format!("redeem script parse: {e}"))?;
                        let mut out: Vec<u8> = Vec::new();
                        for pk_bytes in pubkeys.iter() {
                            for (partial_pub_key, signature) in input.partial_sigs.iter() {
                                let candidate: Vec<u8> = match pk_bytes.len() {
                                    SCHNORR_PUBLIC_KEY_SIZE => partial_pub_key.x_only_public_key().0.serialize().to_vec(),
                                    PUBLIC_KEY_SIZE => partial_pub_key.serialize().to_vec(),
                                    _ => continue,
                                };
                                if candidate.as_slice() == pk_bytes.as_slice() {
                                    out.push(OpData65);
                                    out.extend_from_slice(&(*signature).into_bytes());
                                    out.push(input.sighash_type.to_u8());
                                    break;
                                }
                            }
                        }
                        out
                    }
                    None => input
                        .partial_sigs
                        .values()
                        .flat_map(|signature| {
                            iter::once(OpData65).chain((*signature).into_bytes()).chain([input.sighash_type.to_u8()])
                        })
                        .collect(),
                };

                let redeem_script_push: Vec<u8> = input
                    .redeem_script
                    .as_ref()
                    .map(|redeem_script| {
                        ScriptBuilder::new()
                            .add_data(redeem_script.as_slice())
                            .expect(
                                "multisig redeem script bounded by predicted_multisig_redeem_script_size; \
                                     account-construction guard refuses larger via normalize_and_merge_xpubs",
                            )
                            .drain()
                            .to_vec()
                    })
                    .unwrap_or_default();

                Ok(signatures.into_iter().chain(redeem_script_push).collect())
            })
            .collect::<Result<Vec<_>, _>>()
    });

    match result {
        Ok(finalized_pskt) => Ok(finalized_pskt),
        Err(e) => Err(Error::from(e.to_string())),
    }
}

pub fn finalize_pskt_no_sig_and_redeem_script(pskt: PSKT<Finalizer>) -> Result<PSKT<Finalizer>, Error> {
    let result = pskt.finalize_sync(|inner: &Inner| -> Result<Vec<Vec<u8>>, String> {
        Ok(inner
            .inputs
            .iter()
            .map(|input| -> Vec<u8> {
                input
                    .redeem_script
                    .as_ref()
                    .map(|redeem_script| ScriptBuilder::new().add_data(redeem_script.as_slice()).unwrap().drain().to_vec())
                    .unwrap_or_default()
            })
            .collect())
    });

    match result {
        Ok(finalized_pskt) => Ok(finalized_pskt),
        Err(e) => Err(Error::from(e.to_string())),
    }
}

pub fn bundle_to_finalizer_stream(bundle: &Bundle) -> impl Stream<Item = Result<PSKT<Finalizer>, Error>> + Send {
    stream::iter(bundle.iter().cloned().collect::<Vec<_>>()).map(move |pskt_inner| {
        let pskt: PSKT<Creator> = PSKT::from(pskt_inner);
        let pskt_finalizer = pskt.constructor().updater().signer().finalizer();
        finalize_pskt_one_or_more_sig_and_redeem_script(pskt_finalizer)
    })
}

pub fn pskt_to_pending_transaction(
    finalized_pskt: PSKT<Finalizer>,
    network_id: NetworkId,
    change_address: Address,
    source_utxo_context: Option<UtxoContext>,
) -> Result<PendingTransaction, Error> {
    let inner_pskt = finalized_pskt.deref();
    let (utxo_entries_ref, aggregate_input_value): (Vec<UtxoEntryReference>, u64) = inner_pskt
        .inputs
        .iter()
        .filter_map(|input| {
            input.utxo_entry.as_ref().map(|ue| {
                (
                    UtxoEntryReference {
                        utxo: Arc::new(ClientUTXO {
                            address: Some(extract_script_pub_key_address(&ue.script_public_key, network_id.into()).unwrap()),
                            amount: ue.amount,
                            outpoint: input.previous_outpoint.into(),
                            script_public_key: ue.script_public_key.clone(),
                            block_daa_score: ue.block_daa_score,
                            is_coinbase: ue.is_coinbase,
                            covenant_id: ue.covenant_id,
                        }),
                    },
                    ue.amount,
                )
            })
        })
        .fold((Vec::new(), 0), |(mut vec, sum), (entry, amount)| {
            vec.push(entry);
            (vec, sum + amount)
        });
    let signed_tx = match finalized_pskt.extractor() {
        Ok(extractor) => match extractor.extract_tx(&network_id.into()) {
            Ok(tx) => tx.tx,
            Err(e) => return Err(Error::PendingTransactionFromPSKTError(e.to_string())),
        },
        Err(e) => return Err(Error::PendingTransactionFromPSKTError(e.to_string())),
    };
    let output: &Vec<kaspa_consensus_core::tx::TransactionOutput> = &signed_tx.outputs;
    if output.is_empty() {
        return Err(Error::Custom("0 outputs pskt is not supported".to_string()));
        // todo support 0 outputs
    }
    let recipient = extract_script_pub_key_address(&output[0].script_public_key, network_id.into())?;
    let fee_u: u64 = 0;

    let utxo_iterator: Box<dyn Iterator<Item = UtxoEntryReference> + Send + Sync + 'static> =
        Box::new(utxo_entries_ref.clone().into_iter());

    let final_transaction_destination = PaymentDestination::PaymentOutputs(PaymentOutputs::from((recipient, output[0].value)));

    let settings = GeneratorSettings {
        network_id,
        multiplexer: None,
        sig_op_count: 1,
        minimum_signatures: 1,
        change_address: change_address.clone(),
        utxo_iterator,
        priority_utxo_entries: None,
        source_utxo_context,
        destination_utxo_context: None,
        fee_rate: None,
        final_transaction_priority_fee: fee_u.into(),
        final_transaction_destination,
        final_transaction_payload: None,
    };

    // Create the Generator
    let generator = Generator::try_new(settings, None, None)?;

    let aggregate_output_value = output.iter().map(|output| output.value).sum::<u64>();

    let (change_output_index, change_output_value) = output
        .iter()
        .enumerate()
        .find_map(|(idx, output)| {
            if let Ok(address) = extract_script_pub_key_address(&output.script_public_key, change_address.prefix) {
                if address == change_address { Some((Some(idx), output.value)) } else { None }
            } else {
                None
            }
        })
        .unwrap_or((None, 0));

    // Create PendingTransaction (WIP)
    let addresses = utxo_entries_ref.iter().filter_map(|a| a.address()).collect();
    // todo where the source of mass and fees. why does it equal to zero?
    let pending_tx = PendingTransaction::try_new(
        &generator,
        signed_tx,
        utxo_entries_ref,
        addresses,
        Some(aggregate_output_value),
        change_output_index,
        change_output_value,
        aggregate_input_value,
        aggregate_output_value,
        1,
        0,
        0,
        kaspa_wallet_core::tx::DataKind::Final,
    )?;

    Ok(pending_tx)
}

// Allow creation of atomic commit reveal operation with two
// different parameters sets.
pub enum CommitRevealBatchKind {
    Manual { hop_payment: PaymentDestination, destination_payment: PaymentDestination },
    Parameterized { address: Address, commit_amount_sompi: u64 },
}

struct BundleCommitRevealConfig {
    pub address_commit: Address,
    pub addresses_reveal: Vec<Address>,
    pub commit_destination: PaymentDestination,
    pub redeem_script: Vec<u8>,
    pub payment_outputs: PaymentOutputs,
}

// Create signed atomic commit reveal PSKB.
pub async fn commit_reveal_batch_bundle(
    batch_config: CommitRevealBatchKind,
    reveal_fee_sompi: u64,
    script_sig: Vec<u8>,
    payload: Option<Vec<u8>>,
    fee_rate: Option<f64>,
    account: Arc<dyn Account>,
    wallet_secret: Secret,
    payment_secret: Option<Secret>,
    abortable: &Abortable,
) -> Result<Bundle, Error> {
    let network_id = account.wallet().clone().network_id()?;

    // Configure atomic batch of commit reveal transactions
    let conf: BundleCommitRevealConfig = match batch_config {
        CommitRevealBatchKind::Manual { hop_payment, destination_payment } => {
            let addr_commit = match hop_payment.clone() {
                PaymentDestination::Change => Err(Error::CommitRevealInvalidPaymentDestination),
                PaymentDestination::PaymentOutputs(payment_outputs) => {
                    payment_outputs.outputs.first().map(|out| out.address.clone()).ok_or(Error::CommitRevealEmptyPaymentOutputs)
                }
            }?;

            let (addresses, payment_outputs) = match destination_payment {
                PaymentDestination::Change => Err(Error::CommitRevealInvalidPaymentDestination),
                PaymentDestination::PaymentOutputs(payment_outputs) => {
                    Ok((payment_outputs.outputs.iter().map(|out| out.address.clone()).collect(), payment_outputs))
                }
            }?;

            BundleCommitRevealConfig {
                address_commit: addr_commit,
                addresses_reveal: addresses,
                commit_destination: hop_payment,
                redeem_script: script_sig,
                payment_outputs,
            }
        }
        CommitRevealBatchKind::Parameterized { address, commit_amount_sompi } => {
            let redeem_script = lock_script_sig_templating_bytes(script_sig.to_vec(), Some(&address.payload))
                .map_err(|_| Error::RevealRedeemScriptTemplateError)?;

            let lock_address = script_sig_to_address(&redeem_script, network_id.into())?;

            let amt_reveal: u64 = commit_amount_sompi - reveal_fee_sompi;

            BundleCommitRevealConfig {
                address_commit: lock_address.clone(),
                addresses_reveal: vec![address.clone()],
                commit_destination: PaymentDestination::from(PaymentOutput::new(lock_address, commit_amount_sompi)),
                redeem_script,
                payment_outputs: PaymentOutputs { outputs: vec![PaymentOutput::new(address.clone(), amt_reveal)] },
            }
        }
    };

    // Generate commit transaction
    let settings = GeneratorSettings::try_new_with_account(
        account.clone().as_dyn_arc(),
        conf.commit_destination.clone(),
        fee_rate.or(Some(1.0)),
        0u64.into(),
        payload,
    )
    .map_err(|e| Error::PSKTGenerationError(e.to_string()))?;

    let signer = Arc::new(PSKBSigner::new(
        account.clone().as_dyn_arc(),
        account.prv_key_data(wallet_secret.clone()).await?,
        payment_secret.clone(),
    ));

    let generator = Generator::try_new(settings, None, Some(abortable)).map_err(|e| Error::PSKTGenerationError(e.to_string()))?;

    let pskt_generator = PSKTGenerator::new(generator, signer, account.wallet().address_prefix()?);

    let bundle_commit = bundle_from_pskt_generator(pskt_generator).await.map_err(|e| Error::PSKTGenerationError(e.to_string()))?;

    // Generate reveal transaction
    let bundle_unlock = unlock_utxo_outputs_as_batch_transaction_pskb(
        conf.commit_destination.amount().unwrap(),
        &conf.address_commit,
        &conf.redeem_script,
        conf.payment_outputs.outputs.into_iter().map(|i| (i.address.clone(), i.amount)).collect(),
    )
    .map_err(|e| Error::PSKTGenerationError(e.to_string()))?;

    // Sign and finalize commit transaction
    let (mut merge_bundle, commit_transaction_id) = {
        let signed_pskb = account
            .clone()
            .pskb_sign(&bundle_commit, wallet_secret.clone(), payment_secret.clone(), None)
            .await
            .map_err(|_| Error::CommitTransactionSigningError)?;

        let merge_bundle = Bundle::deserialize(&signed_pskb.serialize()?).map_err(|_| Error::CommitRevealBundleMergeError)?;

        let pskt: PSKT<Signer> = PSKT::<Signer>::from(signed_pskb.as_ref()[0].to_owned());
        let finalizer = pskt.finalizer();

        let pskt_finalizer = finalize_pskt_one_or_more_sig_and_redeem_script(finalizer).map_err(|_| Error::PSKTFinalizationError)?;

        let transaction_id = pskt_to_pending_transaction(
            pskt_finalizer.clone(),
            network_id,
            account.change_address()?,
            account.utxo_context().clone().into(),
        )
        .map_err(|_| Error::CommitTransactionIdExtractionError)?
        .id();
        (merge_bundle, transaction_id)
    };

    // Set commit transaction ID in reveal batch transaction input
    let reveal_pskt: PSKT<Signer> = PSKT::<Signer>::from(bundle_unlock.as_ref()[0].to_owned());
    let unorphaned_bundle_unlock = Bundle::from(reveal_pskt.set_input_prev_transaction_id(commit_transaction_id));

    // Try signing with each reveal address
    for reveal_address in &conf.addresses_reveal {
        if let Ok(signed_pskb) = account
            .clone()
            .pskb_sign(&unorphaned_bundle_unlock, wallet_secret.clone(), payment_secret.clone(), Some(reveal_address))
            .await
        {
            merge_bundle.merge(signed_pskb);
            return Ok(merge_bundle);
        }
    }

    Err(Error::NoQualifiedRevealSignerFound)
}

#[cfg(test)]
mod tests {
    use super::*;
    use kaspa_consensus_core::tx::{TransactionId, TransactionOutpoint, UtxoEntry};
    use kaspa_hashes::HASH_SIZE;
    use kaspa_txscript::opcodes::codes::{Op1, Op2, Op3};
    use kaspa_txscript::{multisig_redeem_script, multisig_redeem_script_ecdsa, pay_to_script_hash_script};
    use kaspa_wallet_pskt::input::InputBuilder;
    use kaspa_wallet_pskt::pskt::Creator;
    use secp256k1::constants::SCHNORR_SIGNATURE_SIZE;
    use secp256k1::{Keypair, Secp256k1, rand::thread_rng};

    // Layout of a single signature push in a P2SH-multisig script_sig:
    // 1-byte OpData65 opcode + Schnorr signature + 1-byte sighash type.
    const SIG_PUSH_LEN: usize = 1 + SCHNORR_SIGNATURE_SIZE + 1;

    /// Parser recovers every Schnorr pubkey from a canonical 2-of-3
    /// redeem-script in source order; pins the load-bearing slot-to-pubkey
    /// mapping the per-cosigner signing path relies on.
    #[test]
    fn test_parse_redeem_script_pubkeys_schnorr_three_keys() {
        let pk1: [u8; SCHNORR_PUBLIC_KEY_SIZE] = [0x11; SCHNORR_PUBLIC_KEY_SIZE];
        let pk2: [u8; SCHNORR_PUBLIC_KEY_SIZE] = [0x22; SCHNORR_PUBLIC_KEY_SIZE];
        let pk3: [u8; SCHNORR_PUBLIC_KEY_SIZE] = [0x33; SCHNORR_PUBLIC_KEY_SIZE];
        let redeem_script = multisig_redeem_script([pk1, pk2, pk3].into_iter(), 2).expect("redeem script");

        let parsed = parse_redeem_script_pubkeys(&redeem_script).expect("parse");

        assert_eq!(parsed.len(), 3, "three pubkeys parsed");
        assert_eq!(parsed[0].as_slice(), &pk1, "first pubkey at slot 0");
        assert_eq!(parsed[1].as_slice(), &pk2, "second pubkey at slot 1");
        assert_eq!(parsed[2].as_slice(), &pk3, "third pubkey at slot 2");
    }

    /// Parser recovers compressed-SEC1 ECDSA pubkeys from a 1-of-2 ECDSA
    /// redeem-script; pins the ECDSA-variant decode path.
    #[test]
    fn test_parse_redeem_script_pubkeys_ecdsa_two_keys() {
        let pk1: [u8; PUBLIC_KEY_SIZE] = [0x44; PUBLIC_KEY_SIZE];
        let pk2: [u8; PUBLIC_KEY_SIZE] = [0x55; PUBLIC_KEY_SIZE];
        let redeem_script = multisig_redeem_script_ecdsa([pk1, pk2].into_iter(), 1).expect("ecdsa redeem script");

        let parsed = parse_redeem_script_pubkeys(&redeem_script).expect("parse ecdsa");

        assert_eq!(parsed.len(), 2, "two ecdsa pubkeys parsed");
        assert_eq!(parsed[0].len(), PUBLIC_KEY_SIZE, "first ecdsa pubkey is a compressed SEC1 key");
        assert_eq!(parsed[0].as_slice(), &pk1);
        assert_eq!(parsed[1].as_slice(), &pk2);
    }

    /// Parser rejects a redeem-script whose OpData32 pushdata is short of
    /// the declared 32-byte pubkey length; pins the truncated-pushdata
    /// rejection arm.
    #[test]
    fn test_parse_redeem_script_pubkeys_rejects_truncated() {
        // Op2 + OpData32 + two arbitrary bytes (the OpData32 pushdata is truncated).
        let truncated: Vec<u8> = vec![Op2, OpData32, 0x11, 0x22];
        assert!(parse_redeem_script_pubkeys(&truncated).is_err(), "truncated OpData32 pushdata rejected");
    }

    /// Parser rejects a redeem-script that omits the trailing
    /// `OpCheckMultiSig` opcode; pins the missing-trailer rejection arm.
    #[test]
    fn test_parse_redeem_script_pubkeys_rejects_missing_trailer() {
        // Op1 then Op3 with nothing after: the trailer claims N=3 but there is no OpCheckMultiSig.
        let no_trailer: Vec<u8> = vec![Op1, Op3];
        assert!(parse_redeem_script_pubkeys(&no_trailer).is_err(), "missing OpCheckMultiSig trailer rejected");
    }

    /// Parser rejects a redeem-script whose trailing N opcode contradicts
    /// the count of pubkeys actually parsed from the body; pins the
    /// trailer-N-mismatch rejection arm.
    #[test]
    fn test_parse_redeem_script_pubkeys_rejects_op_n_mismatch() {
        // K=1, one OpData32 pubkey pushdata, trailer claims N=3, then OpCheckMultiSig.
        // The trailer's N contradicts the actually-parsed pubkey count (1); parser must reject.
        let mut malformed: Vec<u8> = vec![Op1, OpData32];
        malformed.extend_from_slice(&[0xaa; SCHNORR_PUBLIC_KEY_SIZE]);
        malformed.push(Op3);
        malformed.push(OpCheckMultiSig);
        assert!(parse_redeem_script_pubkeys(&malformed).is_err(), "trailer N mismatch with parsed pubkey count rejected");
    }

    /// Parser rejects a redeem-script with trailing bytes after the
    /// `OpCheckMultiSig` terminator; pins the trailing-garbage rejection
    /// arm.
    #[test]
    fn test_parse_redeem_script_pubkeys_rejects_trailing_garbage() {
        // Well-formed 1-of-1 redeem script + one extra trailing byte.
        let mut malformed: Vec<u8> = vec![Op1, OpData32];
        malformed.extend_from_slice(&[0xaa; SCHNORR_PUBLIC_KEY_SIZE]);
        malformed.push(Op1);
        malformed.push(OpCheckMultiSig);
        malformed.push(0xff); // arbitrary trailing byte
        assert!(parse_redeem_script_pubkeys(&malformed).is_err(), "trailing bytes after OpCheckMultiSig rejected");
    }

    /// Pin the RFC 6979 deterministic-nonce invariant the ECDSA-multisig
    /// signing path inherits from `secp256k1::SecretKey::sign_ecdsa`. The
    /// PSKBSigner::sign_ecdsa method wraps exactly the same call sequence
    /// (`SecretKey::from_slice(..)` then `secret_key.sign_ecdsa(message)`),
    /// so the property tested here is the one operators observe through
    /// the PSKB signing path. Cross-binary handoff parity rests on this
    /// invariant: two binaries signing the same (privkey, sighash) pair
    /// emit byte-identical ECDSA signatures whose assembled sigscripts
    /// match bit-for-bit.
    #[test]
    fn multisig_ecdsa_rfc6979_determinism() {
        let secp = Secp256k1::new();
        let keypair = Keypair::new(&secp, &mut thread_rng());
        let secret_key = keypair.secret_key();

        // Two deterministic messages exercising the property across hash
        // values; same-key/same-message pair must yield byte-identical
        // signatures across repeated calls.
        let msg_a = secp256k1::Message::from_digest([0x11u8; 32]);
        let msg_b = secp256k1::Message::from_digest([0xaau8; 32]);

        let sig_a1 = secret_key.sign_ecdsa(msg_a);
        let sig_a2 = secret_key.sign_ecdsa(msg_a);
        let sig_b1 = secret_key.sign_ecdsa(msg_b);
        let sig_b2 = secret_key.sign_ecdsa(msg_b);

        assert_eq!(
            sig_a1.serialize_compact(),
            sig_a2.serialize_compact(),
            "RFC 6979 deterministic: same (privkey, msg_a) pair must yield byte-identical compact signatures",
        );
        assert_eq!(
            sig_b1.serialize_compact(),
            sig_b2.serialize_compact(),
            "RFC 6979 deterministic: same (privkey, msg_b) pair must yield byte-identical compact signatures",
        );
        assert_ne!(
            sig_a1.serialize_compact(),
            sig_b1.serialize_compact(),
            "different messages with the same key must produce distinct signatures (sanity)",
        );
    }

    /// Build a synthetic 17-of-17 multisig redeem script via the canonical
    /// `multisig_redeem_script` helper and assert the parser recovers every
    /// pubkey in source order. Both K=17 and N=17 exceed the small-int
    /// opcode range (`Op1..Op16`); the canonical builder encodes each as a
    /// one-byte PUSHDATA. This exercises the parser's PUSHDATA-int decode
    /// path on both ends and is the smallest K/N pair that does so on both.
    #[test]
    fn test_parse_redeem_script_pubkeys_pushdata_k_and_n_17_of_17() {
        let pubkeys: Vec<[u8; SCHNORR_PUBLIC_KEY_SIZE]> = (0u8..17).map(|i| [i; SCHNORR_PUBLIC_KEY_SIZE]).collect();
        let redeem_script = multisig_redeem_script(pubkeys.iter().copied(), 17).expect("17-of-17 redeem script");
        let parsed = parse_redeem_script_pubkeys(&redeem_script).expect("parse 17-of-17");
        assert_eq!(parsed.len(), 17, "17 pubkeys parsed");
        for (i, expected) in pubkeys.iter().enumerate() {
            assert_eq!(parsed[i].as_slice(), expected, "pubkey at slot {i} matches input");
        }
    }

    /// Build a 13-of-20 multisig redeem script -- K=13 fits the small-int
    /// opcode range and N=20 spills into the one-byte PUSHDATA form.
    /// N=20 is the consensus ceiling (`MAX_PUB_KEYS_PER_MUTLTISIG` at
    /// `kaspa_txscript`); the parser must accept it so the wallet supports
    /// the full consensus-admissible K-of-N range.
    #[test]
    fn test_parse_redeem_script_pubkeys_13_of_20_mixed_int_forms() {
        let pubkeys: Vec<[u8; SCHNORR_PUBLIC_KEY_SIZE]> = (0u8..20).map(|i| [i.wrapping_mul(7); SCHNORR_PUBLIC_KEY_SIZE]).collect();
        let redeem_script = multisig_redeem_script(pubkeys.iter().copied(), 13).expect("13-of-20 redeem script");
        let parsed = parse_redeem_script_pubkeys(&redeem_script).expect("parse 13-of-20");
        assert_eq!(parsed.len(), 20, "20 pubkeys parsed");
        for (i, expected) in pubkeys.iter().enumerate() {
            assert_eq!(parsed[i].as_slice(), expected, "pubkey at slot {i} matches input");
        }
    }

    /// Over-range K or N (> `MAX_PUB_KEYS_PER_MUTLTISIG = 20`) must surface
    /// as a parse error. Wallet-side construction guards refuse over-range
    /// at account-creation time; the parser-side cap is defense-in-depth
    /// for external bundles or future wizards that bypass the construction
    /// guard. Both decode positions (the leading K and the trailing N) are
    /// exercised so neither branch silently accepts a count the consensus
    /// stack-side `OpCheckMultiSig` would later reject as
    /// `InvalidPubKeyCount`.
    #[test]
    fn test_parse_redeem_script_pubkeys_rejects_over_consensus_pub_key_cap() {
        // One above the consensus cap on multisig pubkeys: the smallest value
        // that must be rejected at parse time.
        const OVER_CAP: usize = MAX_PUB_KEYS_PER_MUTLTISIG as usize + 1;
        let pubkeys: Vec<[u8; SCHNORR_PUBLIC_KEY_SIZE]> = (0..OVER_CAP).map(|i| [i as u8; SCHNORR_PUBLIC_KEY_SIZE]).collect();

        // K = OVER_CAP is the very first script integer. The K-decode call
        // refuses before any pubkey is parsed.
        let over_range_k =
            multisig_redeem_script(pubkeys.iter().copied(), OVER_CAP).expect("OVER_CAP-of-OVER_CAP canonical builder output");
        let err_k = parse_redeem_script_pubkeys(&over_range_k).expect_err("over-range K must reject");
        let msg_k = format!("{err_k}");
        assert!(
            msg_k.contains("exceeds the consensus stack-pubkey-count cap"),
            "K-decode rejection names the consensus cap, got: {msg_k}"
        );

        // K = 1 (small-int Op1) with N = OVER_CAP (over-range PUSHDATA
        // trailer): K and pubkeys parse cleanly, then the N-trailer decode
        // hits the cap and refuses before the trailer-vs-pubkey-count
        // consistency check.
        let over_range_n = multisig_redeem_script(pubkeys.iter().copied(), 1).expect("1-of-OVER_CAP canonical builder output");
        let err_n = parse_redeem_script_pubkeys(&over_range_n).expect_err("over-range N trailer must reject");
        let msg_n = format!("{err_n}");
        assert!(
            msg_n.contains("exceeds the consensus stack-pubkey-count cap"),
            "N-decode rejection names the consensus cap, got: {msg_n}"
        );
    }

    /// Builds a 2-of-2 multisig where the redeem-script's pubkey order is the
    /// reverse of the `partial_sigs` BTreeMap iteration order. The finalizer
    /// MUST emit signatures in redeem-script order, not BTreeMap order, so a
    /// downstream `OpCheckMultiSig` walk consumes the signatures in lockstep
    /// with the redeem-script's pubkey-iter and reaches `CleanStack`.
    #[test]
    fn test_finalizer_reorders_by_redeem_script_pubkey_order() {
        let secp = Secp256k1::new();
        let kp_a = Keypair::new(&secp, &mut thread_rng());
        let kp_b = Keypair::new(&secp, &mut thread_rng());
        let pk_a_full = kp_a.public_key();
        let pk_b_full = kp_b.public_key();

        // Choose redeem-script order that DIFFERS from BTreeMap iteration order.
        // BTreeMap orders by `secp256k1::PublicKey`'s `Ord` impl over the 33-byte
        // compressed SEC1 form. We pick the redeem-script's first slot to be the
        // BTreeMap-second key.
        let (rs_first_kp, rs_second_kp) = if pk_a_full < pk_b_full {
            (&kp_b, &kp_a) // BTreeMap iterates a, b -> redeem-script first slot = b
        } else {
            (&kp_a, &kp_b) // BTreeMap iterates b, a -> redeem-script first slot = a
        };

        let rs_first_x = rs_first_kp.x_only_public_key().0.serialize();
        let rs_second_x = rs_second_kp.x_only_public_key().0.serialize();
        let redeem_script = multisig_redeem_script([rs_first_x, rs_second_x].into_iter(), 2).expect("redeem script");

        let msg = secp256k1::Message::from_digest_slice(&[0xab; HASH_SIZE]).expect("msg");
        let sig_a = kp_a.sign_schnorr(msg);
        let sig_b = kp_b.sign_schnorr(msg);
        let mut partial_sigs = kaspa_wallet_pskt::pskt::PartialSigs::new();
        partial_sigs.insert(pk_a_full, Signature::Schnorr(sig_a));
        partial_sigs.insert(pk_b_full, Signature::Schnorr(sig_b));

        let utxo = UtxoEntry {
            amount: 1_000_000,
            script_public_key: pay_to_script_hash_script(redeem_script.as_slice()),
            block_daa_score: 1,
            is_coinbase: false,
            covenant_id: None,
        };
        let mut input = InputBuilder::default()
            .utxo_entry(utxo)
            .previous_outpoint(TransactionOutpoint { transaction_id: TransactionId::from_slice(&[0; HASH_SIZE]), index: 0 })
            .sig_op_count(2)
            .redeem_script(redeem_script.clone())
            .build()
            .expect("input");
        input.partial_sigs = partial_sigs;

        let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
        let pskt_finalizer = pskt_creator.constructor().input(input).updater().signer().finalizer();
        let finalized = finalize_pskt_one_or_more_sig_and_redeem_script(pskt_finalizer).expect("finalize");

        let inner = finalized.deref();
        let script_sig = inner.inputs[0].final_script_sig.as_ref().expect("final_script_sig populated");

        // Each entry layout: 1-byte OpData65 || Schnorr sig || 1-byte sighash_type;
        // SIG_PUSH_LEN packages it.
        assert_eq!(script_sig[0], OpData65, "first signature opcode");
        let first_sig_bytes = &script_sig[1..1 + SCHNORR_SIGNATURE_SIZE];
        let rs_first_expected_sig = if std::ptr::eq(rs_first_kp, &kp_a) { sig_a.serialize() } else { sig_b.serialize() };
        assert_eq!(first_sig_bytes, &rs_first_expected_sig, "first emitted signature matches redeem-script's first pubkey");

        assert_eq!(script_sig[SIG_PUSH_LEN], OpData65, "second signature opcode");
        let second_sig_bytes = &script_sig[SIG_PUSH_LEN + 1..SIG_PUSH_LEN + 1 + SCHNORR_SIGNATURE_SIZE];
        let rs_second_expected_sig = if std::ptr::eq(rs_second_kp, &kp_a) { sig_a.serialize() } else { sig_b.serialize() };
        assert_eq!(second_sig_bytes, &rs_second_expected_sig, "second emitted signature matches redeem-script's second pubkey");

        // Counterfactual: assert the actual emitted order DIFFERS from what a
        // pre-reorder Finalizer (BTreeMap iteration order) would have produced.
        // BTreeMap iterates by `secp256k1::PublicKey`'s `Ord` impl over the
        // 33-byte compressed SEC1 form; we picked `rs_first_kp` to be the
        // BTreeMap-second key, so a pre-reorder Finalizer would have emitted
        // the BTreeMap-first key's sig at offset [1..65].
        let btreemap_first_kp = if pk_a_full < pk_b_full { &kp_a } else { &kp_b };
        let btreemap_first_expected_sig = if std::ptr::eq(btreemap_first_kp, &kp_a) { sig_a.serialize() } else { sig_b.serialize() };
        assert_ne!(
            first_sig_bytes, &btreemap_first_expected_sig,
            "Finalizer's first-emitted signature must differ from what BTreeMap iteration order would produce",
        );
    }

    /// Drive the Finalizer through `TxScriptEngine::execute()` over a
    /// parametric matrix of K-of-N cells crossed with the Schnorr and ECDSA
    /// multisig schemes. For each cell the test builds a synthetic transaction
    /// whose input spends a P2SH output committed to a redeem script whose
    /// pubkey order has been chosen to differ from `secp256k1::PublicKey`'s
    /// `Ord` order (the order `BTreeMap<PublicKey, _>` iterates), then signs
    /// with K of the N cosigners, drives `PartialSigs` through the Finalizer
    /// reorder body, sets the result as the input's `signature_script`, and
    /// asserts `TxScriptEngine::execute()` returns `Ok(())`. A complementary
    /// arm bypasses the reorder by emitting the same K signatures in
    /// `BTreeMap` iteration order directly and asserts the script engine
    /// rejects the resulting consensus walk -- pinning that the SAME setup
    /// with the reorder removed fails consensus and demonstrating that the
    /// reorder body is load-bearing for the `OpCheckMultiSig` forward-walk's
    /// irreversible pubkey-iter consumption.
    #[test]
    fn test_finalizer_reorders_property_over_k_of_n_cells() {
        use kaspa_consensus_core::hashing::sighash::calc_ecdsa_signature_hash;
        use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
        use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
        use kaspa_consensus_core::tx::{MutableTransaction, Transaction, TransactionInput, TransactionOutpoint, UtxoEntry};
        use kaspa_txscript::caches::Cache;
        use kaspa_txscript::{EngineCtx, TxScriptEngine, pay_to_script_hash_script};

        // K-of-N cells exercised in the multi-cosigner send tests. The (1, 1)
        // cell is excluded per the existing single-key P2PK topology
        // divergence (see `create_address`).
        let cells: &[(usize, usize)] = &[(2, 2), (2, 3), (3, 5)];
        let secp = Secp256k1::new();

        for &(k, n) in cells {
            for &is_ecdsa in &[false, true] {
                // Generate N keypairs and sort by the order BTreeMap<PublicKey, _>
                // iterates (the secp256k1::PublicKey `Ord` impl over the 33-byte
                // compressed form). Pick the redeem-script pubkey order to be the
                // reverse of that BTreeMap order so the Finalizer's reorder body
                // has nontrivial work to do.
                let mut keypairs: Vec<Keypair> = (0..n).map(|_| Keypair::new(&secp, &mut thread_rng())).collect();
                keypairs.sort_by_key(|kp| kp.public_key());
                let rs_pubkeys_btmap_reverse: Vec<&Keypair> = keypairs.iter().rev().collect();

                // Build the redeem script in the reversed-BTreeMap-order. Schnorr
                // uses 32-byte x-only pubkeys; ECDSA uses 33-byte compressed.
                let redeem_script = if is_ecdsa {
                    let pks: Vec<[u8; PUBLIC_KEY_SIZE]> =
                        rs_pubkeys_btmap_reverse.iter().map(|kp| kp.public_key().serialize()).collect();
                    kaspa_txscript::multisig_redeem_script_ecdsa(pks.iter().copied(), k).expect("ecdsa redeem script")
                } else {
                    let pks: Vec<[u8; SCHNORR_PUBLIC_KEY_SIZE]> =
                        rs_pubkeys_btmap_reverse.iter().map(|kp| kp.x_only_public_key().0.serialize()).collect();
                    multisig_redeem_script(pks.iter().copied(), k).expect("schnorr redeem script")
                };

                // Synthetic transaction whose single input spends a P2SH UTXO
                // committed to the redeem script.
                let prev_outpoint = TransactionOutpoint { transaction_id: TransactionId::from_slice(&[0xab; HASH_SIZE]), index: 0 };
                let tx_in = TransactionInput {
                    previous_outpoint: prev_outpoint,
                    signature_script: vec![],
                    sequence: 0,
                    compute_commit: kaspa_consensus_core::mass::SigopCount(n as u8).into(),
                };
                let tx = Transaction::new(0, vec![tx_in], vec![], 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
                let entry = UtxoEntry {
                    amount: 1_000_000,
                    script_public_key: pay_to_script_hash_script(redeem_script.as_slice()),
                    block_daa_score: 1,
                    is_coinbase: false,
                    covenant_id: None,
                };

                // Compute the sighash so signatures verify under the engine.
                let mut signing_tx = MutableTransaction::with_entries(tx.clone(), vec![entry.clone()]);
                let reused_values = SigHashReusedValuesUnsync::new();
                let sig_hash = if is_ecdsa {
                    calc_ecdsa_signature_hash(&signing_tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values)
                } else {
                    calc_schnorr_signature_hash(&signing_tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values)
                };
                let msg = secp256k1::Message::from_digest_slice(sig_hash.as_bytes().as_slice()).expect("msg");

                // Sign with the first K keypairs (any K of the N suffices for K-of-N).
                let signers: Vec<&Keypair> = keypairs.iter().take(k).collect();
                let mut partial_sigs = kaspa_wallet_pskt::pskt::PartialSigs::new();
                for kp in signers.iter() {
                    let sig = if is_ecdsa {
                        Signature::ECDSA(kp.secret_key().sign_ecdsa(msg))
                    } else {
                        Signature::Schnorr(kp.sign_schnorr(msg))
                    };
                    partial_sigs.insert(kp.public_key(), sig);
                }

                // Build a PSKT input carrying the partial sigs + redeem_script and
                // run it through the Finalizer.
                let mut input = InputBuilder::default()
                    .utxo_entry(entry.clone())
                    .previous_outpoint(prev_outpoint)
                    .sig_op_count(n as u8)
                    .redeem_script(redeem_script.clone())
                    .build()
                    .expect("input");
                input.partial_sigs = partial_sigs.clone();
                let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
                let pskt_finalizer = pskt_creator.constructor().input(input).updater().signer().finalizer();
                let finalized = finalize_pskt_one_or_more_sig_and_redeem_script(pskt_finalizer).expect("finalize");
                let inner = finalized.deref();
                let reordered_script_sig = inner.inputs[0].final_script_sig.clone().expect("final_script_sig populated");

                // Positive arm: ordered script_sig passes consensus-script-verify.
                signing_tx.tx.inputs[0].signature_script = reordered_script_sig;
                let verifiable = signing_tx.as_verifiable();
                let (vtx_in, vtx_entry) = verifiable.populated_inputs().next().expect("populated input");
                let cache = Cache::new(10_000);
                let ctx = EngineCtx::new(&cache).with_reused(&reused_values);
                let mut engine = TxScriptEngine::from_transaction_input(&verifiable, vtx_in, 0, vtx_entry, ctx, Default::default());
                assert!(
                    engine.execute().is_ok(),
                    "({k}-of-{n}, ecdsa={is_ecdsa}): ordered script_sig must pass TxScriptEngine::execute",
                );

                // Negative arm: BTreeMap-order signatures (skipping the Finalizer
                // reorder) emit sigs in `secp256k1::PublicKey::Ord` order, which
                // for this fixture is the reverse of redeem-script order; the
                // consensus walk's irreversible pubkey-iter consumption then
                // abandons the walk and the engine rejects.
                let mut btmap_only: Vec<u8> = Vec::new();
                for (_pk, signature) in partial_sigs.iter() {
                    btmap_only.push(OpData65);
                    btmap_only.extend_from_slice(&(*signature).into_bytes());
                    btmap_only.push(SIG_HASH_ALL.to_u8());
                }
                btmap_only
                    .extend(kaspa_txscript::script_builder::ScriptBuilder::new().add_data(redeem_script.as_slice()).unwrap().drain());
                let mut signing_tx_neg = MutableTransaction::with_entries(tx.clone(), vec![entry.clone()]);
                signing_tx_neg.tx.inputs[0].signature_script = btmap_only;
                let verifiable_neg = signing_tx_neg.as_verifiable();
                let (vneg_in, vneg_entry) = verifiable_neg.populated_inputs().next().expect("populated input");
                let cache_neg = Cache::new(10_000);
                let ctx_neg = EngineCtx::new(&cache_neg).with_reused(&reused_values);
                let mut engine_neg =
                    TxScriptEngine::from_transaction_input(&verifiable_neg, vneg_in, 0, vneg_entry, ctx_neg, Default::default());
                assert!(
                    engine_neg.execute().is_err(),
                    "({k}-of-{n}, ecdsa={is_ecdsa}): unordered (map iteration order) script_sig must fail TxScriptEngine::execute",
                );
            }
        }
    }

    /// An input whose `partial_sigs` count exceeds its redeem-script threshold
    /// is declined by the Finalizer with `FinalizerExcessSignatures` rather
    /// than collated into an over-long signature stack. Here a 2-of-3 redeem
    /// script (threshold 2) carries three partial signatures.
    #[test]
    fn test_finalizer_excess_signatures_error() {
        let secp = Secp256k1::new();
        let kp_a = Keypair::new(&secp, &mut thread_rng());
        let kp_b = Keypair::new(&secp, &mut thread_rng());
        let kp_c = Keypair::new(&secp, &mut thread_rng());

        let x_a = kp_a.x_only_public_key().0.serialize();
        let x_b = kp_b.x_only_public_key().0.serialize();
        let x_c = kp_c.x_only_public_key().0.serialize();
        let threshold = 2usize;
        let redeem_script = multisig_redeem_script([x_a, x_b, x_c].into_iter(), threshold).expect("redeem script");

        let msg = secp256k1::Message::from_digest_slice(&[0xcd; HASH_SIZE]).expect("msg");
        let mut partial_sigs = kaspa_wallet_pskt::pskt::PartialSigs::new();
        partial_sigs.insert(kp_a.public_key(), Signature::Schnorr(kp_a.sign_schnorr(msg)));
        partial_sigs.insert(kp_b.public_key(), Signature::Schnorr(kp_b.sign_schnorr(msg)));
        partial_sigs.insert(kp_c.public_key(), Signature::Schnorr(kp_c.sign_schnorr(msg)));

        let utxo = UtxoEntry {
            amount: 1_000_000,
            script_public_key: pay_to_script_hash_script(redeem_script.as_slice()),
            block_daa_score: 1,
            is_coinbase: false,
            covenant_id: None,
        };
        let mut input = InputBuilder::default()
            .utxo_entry(utxo)
            .previous_outpoint(TransactionOutpoint { transaction_id: TransactionId::from_slice(&[0; HASH_SIZE]), index: 0 })
            .sig_op_count(threshold as u8)
            .redeem_script(redeem_script.clone())
            .build()
            .expect("input");
        input.partial_sigs = partial_sigs;

        let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
        let pskt_finalizer = pskt_creator.constructor().input(input).updater().signer().finalizer();

        match finalize_pskt_one_or_more_sig_and_redeem_script(pskt_finalizer) {
            Err(Error::FinalizerExcessSignatures { found, allowed, input_index }) => {
                assert_eq!(found, 3, "three partial signatures present");
                assert_eq!(allowed, threshold as u16, "redeem-script threshold");
                assert_eq!(input_index, 0, "violating input index");
            }
            Ok(_) => panic!("expected FinalizerExcessSignatures, got a finalized PSKT"),
            Err(other) => panic!("expected FinalizerExcessSignatures, got {other:?}"),
        }
    }

    /// The excess-signature guard applies only to multisig redeem scripts. A
    /// non-multisig redeem script (here a single `OP_1` envelope) carrying more
    /// signatures than its leading small-int would imply must NOT be rejected
    /// with `FinalizerExcessSignatures` -- the guard skips it so the
    /// commit-reveal / non-multisig finalize path is left untouched.
    #[test]
    fn test_finalizer_excess_guard_skips_non_multisig_redeem() {
        let secp = Secp256k1::new();
        let kp_a = Keypair::new(&secp, &mut thread_rng());
        let kp_b = Keypair::new(&secp, &mut thread_rng());

        // OP_1 envelope: a valid script integer (decodes to 1) but NOT a
        // multisig redeem script (no pubkeys, no OpCheckMultiSig trailer).
        let redeem_script = vec![Op1];

        let msg = secp256k1::Message::from_digest_slice(&[0xef; HASH_SIZE]).expect("msg");
        let mut partial_sigs = kaspa_wallet_pskt::pskt::PartialSigs::new();
        partial_sigs.insert(kp_a.public_key(), Signature::Schnorr(kp_a.sign_schnorr(msg)));
        partial_sigs.insert(kp_b.public_key(), Signature::Schnorr(kp_b.sign_schnorr(msg)));

        let utxo = UtxoEntry {
            amount: 1_000_000,
            script_public_key: pay_to_script_hash_script(redeem_script.as_slice()),
            block_daa_score: 1,
            is_coinbase: false,
            covenant_id: None,
        };
        let mut input = InputBuilder::default()
            .utxo_entry(utxo)
            .previous_outpoint(TransactionOutpoint { transaction_id: TransactionId::from_slice(&[0; HASH_SIZE]), index: 0 })
            .sig_op_count(1)
            .redeem_script(redeem_script.clone())
            .build()
            .expect("input");
        input.partial_sigs = partial_sigs;

        let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
        let pskt_finalizer = pskt_creator.constructor().input(input).updater().signer().finalizer();

        // The guard must not fire for a non-multisig redeem. (Finalization of a
        // non-multisig redeem may still fail downstream in the emission loop --
        // that is a separate, pre-existing concern -- but it must never be
        // `FinalizerExcessSignatures`.)
        if let Err(Error::FinalizerExcessSignatures { .. }) = finalize_pskt_one_or_more_sig_and_redeem_script(pskt_finalizer) {
            panic!("excess-signature guard must skip non-multisig redeem scripts");
        }
    }
}
