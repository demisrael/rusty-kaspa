//! Transaction signing. Mirrors the Go reference at
//! `https://github.com/kaspanet/kaspad/blob/master/cmd/kaspawallet/libkaspawallet/sign.go`
//! but reuses rusty-kaspa primitives for the BIP-32 derivation
//! (`kaspa-bip32`), the per-input sighash computation
//! (`kaspa-consensus-core::hashing::sighash::{calc_schnorr_signature_hash,
//! calc_ecdsa_signature_hash}`), and the underlying ECDSA / Schnorr
//! signing operations (`secp256k1::Keypair::sign_schnorr`,
//! `secp256k1::SecretKey::sign_ecdsa`).
//!
//! Phase 1 scope of this module: single-cosigner sign of a
//! `PartiallySignedTransaction` in both Schnorr and ECDSA modes.
//! Multisig partial-sig combination is a deliberate follow-on; the
//! cross-wallet interop AC's wire-format half is already verified
//! by the cross-binary PST byte-identity test in
//! `serialization::tests`. This module contributes the sign-flow
//! half (a Rust-signed PST whose Schnorr signature verifies under
//! the cosigner's derived x-only pubkey and whose ECDSA signature
//! is byte-identical to the Go signing's output on the same
//! `(privkey, sighash)` pair, produced via rusty-kaspa sighash +
//! secp256k1 signing surfaces -- no rolled crypto).

pub(crate) mod combine;
mod derive;
mod ecdsa;
mod error;
mod schnorr;
pub(crate) mod wire;

#[cfg(test)]
mod tests;

pub use combine::extract_transaction;
pub use ecdsa::sign_pst_ecdsa_with_mnemonic;
pub use error::SignError;
pub use schnorr::sign_pst_schnorr_with_mnemonic;

/// True when every input of the PST has at least
/// `minimum_signatures` non-empty signatures. Mirrors Go
/// `cmd/kaspawallet/libkaspawallet/transaction.go::isTransactionFullySigned`.
pub fn is_pst_fully_signed(pst: &crate::serialization::wire::PartiallySignedTransaction) -> bool {
    for input in &pst.partially_signed_inputs {
        let n: u32 = input.pub_key_signature_pairs.iter().filter(|p| !p.signature.is_empty()).count() as u32;
        if n < input.minimum_signatures {
            return false;
        }
    }
    true
}
