//! Keyfile-backed `KeySource` implementation. Addresses are
//! derived at `m/<purpose>'/111111'/0'/<chain>/<index>`; the
//! keyfile's `publicKeys` array stores the per-cosigner xpub
//! already at level `m/<purpose>'/111111'/0'`, so per-address
//! derivation is a non-hardened `<chain>/<index>` walk off each
//! stored xpub.
//!
//! For single-cosigner keyfiles the derived public key is encoded
//! directly as a P2PK address (Schnorr or ECDSA per the keyfile's
//! `ecdsa` flag). For multi-cosigner keyfiles the cosigner xpubs
//! are lexicographically sorted, each xpub is derived at the same
//! `<chain>/<index>`, the per-index public keys are passed to
//! `multisig_redeem_script`, and the redeem script's blake2b-256
//! hash becomes the payload of a `ScriptHash` address.

use std::cell::Cell;
use std::str::FromStr;

use kaspa_addresses::{Address, Prefix as AddressPrefix, Version as AddressVersion};
use kaspa_bip32::{ChildNumber, DerivationPath, ExtendedPrivateKey, ExtendedPublicKey, Language, Mnemonic, SecretKey};
use kaspa_consensus_core::hashing::sighash_type::SIG_HASH_ALL;
use kaspa_txscript::{multisig_redeem_script, multisig_redeem_script_ecdsa};
use zeroize::Zeroizing;

use crate::keyfile::KeysFile;

use super::error::KeySourceError;
use super::resolver::KeyChain;
use super::traits::{DerivableKeySource, KeySource};

/// Blake2b output length (bytes) used for P2SH script hashing.
/// Matches the kaspa-txscript `pay_to_script_hash_script` hash
/// length constant.
const SCRIPT_HASH_LEN: usize = 32;

/// Sighash digest length (bytes) the `sign_for` entry point expects.
/// Both Schnorr (BIP-340) and ECDSA (`secp256k1`) sign over a
/// 32-byte digest.
const SIGHASH_DIGEST_LEN: usize = 32;

/// Raw signature length (bytes) for both supported curves. Schnorr
/// BIP-340 signatures are 64 bytes; ECDSA compact serialization
/// (`Signature::serialize_compact`) is also 64 bytes.
const RAW_SIGNATURE_LEN: usize = 64;

/// BIP-43 purpose component for single-signer wallets.
const SINGLE_SIGNER_PURPOSE: u32 = 44;

/// BIP-43-style purpose component for multisig wallets.
const MULTISIG_PURPOSE: u32 = 45;

/// Kaspa SLIP-0044 coin-type component.
const COIN_TYPE: u32 = 111111;

/// Concrete `LegacyGoKeyfile` key source. Holds the decoded
/// keyfile fields plus a lexicographically-sorted xpub view that
/// the multisig derivation path uses without re-sorting per call.
pub struct LegacyGoKeyfile {
    extended_public_keys_sorted: Vec<String>,
    minimum_signatures: u32,
    ecdsa: bool,
    cosigner_count: u32,
    last_used_external_index: Cell<u32>,
    last_used_internal_index: Cell<u32>,
    address_prefix: AddressPrefix,
    /// Decrypted mnemonics. Populated when the keyfile was opened
    /// with a password and signing might happen later. Consumed
    /// by `sign_for` -- the per-input signing entry point on the
    /// `KeySource` trait. Wrapped in `Zeroizing` so plaintext
    /// mnemonic bytes are scrubbed when this `LegacyGoKeyfile`
    /// is dropped.
    decrypted_mnemonics: Zeroizing<Vec<String>>,
}

impl LegacyGoKeyfile {
    /// Open a keyfile under the given password and address prefix.
    /// Decrypts every mnemonic (Argon2id + XChaCha20-Poly1305) and
    /// captures the sorted xpub view used by the multisig
    /// derivation path. The `password` slice is borrowed only for
    /// the duration of this call.
    pub fn open(keyfile: KeysFile, password: &[u8], address_prefix: AddressPrefix) -> Result<Self, KeySourceError> {
        let decrypted_mnemonics = crate::keyfile::decrypt_mnemonics(&keyfile, password)?;

        let mut sorted = keyfile.extended_public_keys.clone();
        sorted.sort();

        let cosigner_count = u32::try_from(keyfile.extended_public_keys.len())
            .map_err(|_| KeySourceError::Invalid { field: "publicKeys", reason: "too many cosigners".into() })?;
        if cosigner_count < keyfile.minimum_signatures {
            return Err(KeySourceError::Invalid {
                field: "minimumSignatures",
                reason: format!("minimum signatures {} exceeds cosigner count {cosigner_count}", keyfile.minimum_signatures,),
            });
        }

        Ok(Self {
            extended_public_keys_sorted: sorted,
            minimum_signatures: keyfile.minimum_signatures,
            ecdsa: keyfile.ecdsa,
            cosigner_count,
            last_used_external_index: Cell::new(keyfile.last_used_external_index),
            last_used_internal_index: Cell::new(keyfile.last_used_internal_index),
            address_prefix,
            decrypted_mnemonics,
        })
    }

    fn is_multisig(&self) -> bool {
        self.extended_public_keys_sorted.len() > 1
    }

    fn next_index(&self, chain: KeyChain) -> u32 {
        match chain {
            KeyChain::External => {
                let n = self.last_used_external_index.get();
                self.last_used_external_index.set(n.wrapping_add(1));
                n
            }
            KeyChain::Internal => {
                let n = self.last_used_internal_index.get();
                self.last_used_internal_index.set(n.wrapping_add(1));
                n
            }
        }
    }

    fn derive_xpub(xpub: &str, chain: KeyChain, idx: u32) -> Result<secp256k1::PublicKey, KeySourceError> {
        let parsed = ExtendedPublicKey::<secp256k1::PublicKey>::from_str(xpub)?;
        let chain_child = parsed.derive_child(ChildNumber::new(chain.index(), false)?)?;
        let leaf = chain_child.derive_child(ChildNumber::new(idx, false)?)?;
        Ok(*leaf.public_key())
    }

    fn single_key_address(&self, chain: KeyChain, idx: u32) -> Result<Address, KeySourceError> {
        let pubkey = Self::derive_xpub(&self.extended_public_keys_sorted[0], chain, idx)?;
        Ok(if self.ecdsa {
            Address::new(self.address_prefix, AddressVersion::PubKeyECDSA, &pubkey.serialize())
        } else {
            Address::new(self.address_prefix, AddressVersion::PubKey, &pubkey.x_only_public_key().0.serialize())
        })
    }

    fn multisig_address(&self, chain: KeyChain, idx: u32) -> Result<Address, KeySourceError> {
        let mut leaf_pubkeys = Vec::with_capacity(self.extended_public_keys_sorted.len());
        for xpub in &self.extended_public_keys_sorted {
            leaf_pubkeys.push(Self::derive_xpub(xpub, chain, idx)?);
        }
        let required = usize::try_from(self.minimum_signatures)
            .map_err(|_| KeySourceError::Invalid { field: "minimumSignatures", reason: "exceeds usize".into() })?;

        let redeem_script = if self.ecdsa {
            let serialized: Vec<[u8; 33]> = leaf_pubkeys.iter().map(|p| p.serialize()).collect();
            multisig_redeem_script_ecdsa(serialized.iter(), required).map_err(|e| KeySourceError::RedeemScript(e.to_string()))?
        } else {
            let serialized: Vec<[u8; 32]> = leaf_pubkeys.iter().map(|p| p.x_only_public_key().0.serialize()).collect();
            multisig_redeem_script(serialized.iter(), required).map_err(|e| KeySourceError::RedeemScript(e.to_string()))?
        };

        let hash = blake2b_simd::Params::new().hash_length(SCRIPT_HASH_LEN).to_state().update(&redeem_script).finalize();
        Ok(Address::new(self.address_prefix, AddressVersion::ScriptHash, hash.as_bytes()))
    }

    fn address_at(&self, chain: KeyChain, idx: u32) -> Result<Address, KeySourceError> {
        if self.is_multisig() { self.multisig_address(chain, idx) } else { self.single_key_address(chain, idx) }
    }
}

impl KeySource for LegacyGoKeyfile {
    fn cosigner_count(&self) -> u32 {
        self.cosigner_count
    }

    fn receiving_address(&self, idx: Option<u32>) -> Result<Address, KeySourceError> {
        let i = idx.unwrap_or_else(|| self.next_index(KeyChain::External));
        self.address_at(KeyChain::External, i)
    }

    fn change_address(&self) -> Result<Address, KeySourceError> {
        let i = self.next_index(KeyChain::Internal);
        self.address_at(KeyChain::Internal, i)
    }

    fn sign_for(&self, cosigner_idx: u32, derivation_path: &str, msg: &[u8]) -> Result<Vec<u8>, KeySourceError> {
        let mnemonic_count = self.decrypted_mnemonics.len();
        let idx = usize::try_from(cosigner_idx).ok().filter(|i| *i < mnemonic_count).ok_or_else(|| KeySourceError::Invalid {
            field: "cosigner_idx",
            reason: format!("cosigner_idx {cosigner_idx} out of range; this keyfile holds {mnemonic_count} cosigner mnemonic(s)"),
        })?;
        if msg.len() != SIGHASH_DIGEST_LEN {
            return Err(KeySourceError::Invalid {
                field: "msg",
                reason: format!("expected a {SIGHASH_DIGEST_LEN}-byte sighash digest, got {} bytes", msg.len()),
            });
        }

        // Derive the leaf signing key: master <- seed(mnemonic) ->
        // cosigner prefix walk (purpose / coin / 0') -> relative
        // path walk (the input's `derivation_path` field of the
        // PartiallySignedInput, e.g. "m/0/3").
        let mnemonic = Mnemonic::new(self.decrypted_mnemonics[idx].as_str(), Language::English)?;
        let seed = mnemonic.to_seed("");
        let master = ExtendedPrivateKey::<SecretKey>::new(seed.as_bytes())?;
        let purpose = if self.is_multisig() { MULTISIG_PURPOSE } else { SINGLE_SIGNER_PURPOSE };
        let cosigner_prefix = DerivationPath::from_str(&format!("m/{purpose}'/{COIN_TYPE}'/0'"))?;
        let relative = DerivationPath::from_str(derivation_path)?;
        let leaf = master.derive_path(&cosigner_prefix)?.derive_path(&relative)?;
        let secret_key = *leaf.private_key();

        let sighash_msg = secp256k1::Message::from_digest_slice(msg)?;
        let sig_bytes: [u8; RAW_SIGNATURE_LEN] = if self.ecdsa {
            secret_key.sign_ecdsa(sighash_msg).serialize_compact()
        } else {
            let keypair = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &secret_key);
            *keypair.sign_schnorr(sighash_msg).as_ref()
        };

        let mut sig_with_hash_type = Vec::with_capacity(RAW_SIGNATURE_LEN + 1);
        sig_with_hash_type.extend_from_slice(&sig_bytes);
        sig_with_hash_type.push(SIG_HASH_ALL.to_u8());
        Ok(sig_with_hash_type)
    }
}

impl DerivableKeySource for LegacyGoKeyfile {
    fn extended_public_keys(&self) -> &[String] {
        &self.extended_public_keys_sorted
    }

    fn chain_addresses(&self, chain: KeyChain, range: core::ops::Range<u32>) -> Result<Vec<Address>, KeySourceError> {
        let mut out = Vec::with_capacity(range.len());
        for i in range {
            out.push(self.address_at(chain, i)?);
        }
        Ok(out)
    }
}
