//! Legacy Go-keyfile `KeySource` implementation. The Go reference
//! derives addresses at
//! `m/<purpose>'/111111'/0'/<chain>/<index>`; the keyfile's
//! `publicKeys` array stores the per-cosigner xpub already at
//! level `m/<purpose>'/111111'/0'`, so per-address derivation is a
//! non-hardened `<chain>/<index>` walk off each stored xpub.
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
use kaspa_bip32::{ChildNumber, ExtendedPublicKey};
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
    /// with a password and signing might happen later. Kept
    /// off-thread; the sign module consumes this in a follow-on
    /// batch. Wrapped in `Zeroizing` so plaintext mnemonic bytes are
    /// scrubbed when this `LegacyGoKeyfile` is dropped.
    #[allow(dead_code)] // Consumed by the sign module in a follow-on batch.
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
