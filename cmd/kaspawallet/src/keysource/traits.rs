//! Key-source trait surface. Every backend the wallet supports
//! implements `KeySource`; backends that expose a BIP-32
//! derivation chain additionally implement `DerivableKeySource`.
//! The split exists so single-address backends (e.g., Tangem)
//! can return a fixed receiving address without faking a
//! derivation chain.

use kaspa_addresses::Address;

use super::error::KeySourceError;
use super::resolver::KeyChain;

/// Base capability: every backend can name its cosigner count,
/// produce a receiving / change address, and sign a per-input
/// sighash digest with one of its cosigner keys.
pub trait KeySource {
    /// Number of cosigners the backend holds. `1` for single-sig.
    fn cosigner_count(&self) -> u32;

    /// Receiving (external) address at an explicit index, or the
    /// next unused index when `idx == None`. Backends that do not
    /// hold a chain (Tangem) return the same address regardless of
    /// `idx`.
    fn receiving_address(&self, idx: Option<u32>) -> Result<Address, KeySourceError>;

    /// Change (internal) address. Single-address backends (e.g.
    /// Tangem) return the same address `receiving_address`
    /// produces -- "all change coming back to same address". The
    /// `LegacyGoKeyfile` backend returns the next unused
    /// internal-chain address.
    fn change_address(&self) -> Result<Address, KeySourceError>;

    /// Sign a 32-byte per-input sighash digest. `cosigner_idx`
    /// selects which of the backend's available cosigner keys
    /// signs (single-cosigner backends accept only `0`);
    /// `derivation_path` is the path -- relative to the backend's
    /// cosigner prefix -- that identifies the leaf signing key
    /// (matches a `PartiallySignedInput.derivation_path`); `msg` is
    /// the 32-byte sighash bytes the caller has already computed
    /// for the input.
    ///
    /// Returns the 65-byte signature-plus-sighash-type blob that the
    /// wire-format `PubKeySignaturePair.signature` field stores:
    /// the 64-byte raw signature (Schnorr BIP-340 64-byte form, or
    /// 64-byte compact ECDSA serialization), followed by a single
    /// `SIG_HASH_ALL` byte.
    fn sign_for(&self, cosigner_idx: u32, derivation_path: &str, msg: &[u8]) -> Result<Vec<u8>, KeySourceError>;
}

/// Optional capability: backends that hold a BIP-32 derivation
/// chain expose batch derivation for `show-addresses` and a
/// `derive_address` accessor for parity tests / fixture
/// validation. Default-implemented `derive_address` exists so
/// callers can address either chain through a single entry point.
pub trait DerivableKeySource: KeySource {
    /// Lexicographically-sorted extended public keys (xpub
    /// strings) that anchor the derivation chains. Used for
    /// multisig address derivation (sort + per-cosigner derive)
    /// and for serialization parity tests.
    fn extended_public_keys(&self) -> &[String];

    /// Derive a range of addresses on the requested chain.
    fn chain_addresses(&self, chain: KeyChain, range: core::ops::Range<u32>) -> Result<Vec<Address>, KeySourceError>;

    /// Derive a single address on the requested chain at a fixed
    /// index. Returned address is consistent with the value
    /// `chain_addresses` would produce for a one-index range
    /// containing `idx`.
    fn derive_address(&self, chain: KeyChain, idx: u32) -> Result<Address, KeySourceError> {
        let mut out = self.chain_addresses(chain, idx..idx + 1)?;
        out.pop().ok_or(KeySourceError::Invalid { field: "chain_addresses", reason: "empty range".into() })
    }
}
