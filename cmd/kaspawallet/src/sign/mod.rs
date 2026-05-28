//! Transaction signing. Reuses rusty-kaspa primitives for the
//! BIP-32 derivation (`kaspa-bip32`), the per-input sighash
//! computation
//! (`kaspa-consensus-core::hashing::sighash::{calc_schnorr_signature_hash,
//! calc_ecdsa_signature_hash}`), and the underlying ECDSA /
//! Schnorr signing operations
//! (`secp256k1::Keypair::sign_schnorr`,
//! `secp256k1::SecretKey::sign_ecdsa`).
//!
//! Single-cosigner sign of a `PartiallySignedTransaction` is
//! covered in both Schnorr and ECDSA modes. The cross-wallet
//! interop AC's wire-format half is verified by the cross-
//! implementation PST byte-identity test in
//! `serialization::tests`; this module contributes the sign-flow
//! half (a Rust-signed PST whose Schnorr signature verifies under
//! the cosigner's derived x-only pubkey and whose ECDSA signature
//! is byte-identical to the reference output on the same
//! `(privkey, sighash)` pair).

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
/// `minimum_signatures` non-empty signatures.
pub fn is_pst_fully_signed(pst: &crate::serialization::wire::PartiallySignedTransaction) -> bool {
    for input in &pst.partially_signed_inputs {
        let n: u32 = input.pub_key_signature_pairs.iter().filter(|p| !p.signature.is_empty()).count() as u32;
        if n < input.minimum_signatures {
            return false;
        }
    }
    true
}
