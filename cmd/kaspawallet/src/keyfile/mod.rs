//! Legacy Go-`kaspawallet` keyfile native read.
//!
//! On-disk format: JSON.
//!
//! Fields mirror the Go `keysFileJSON` struct at
//! `https://github.com/kaspanet/kaspad/blob/master/cmd/kaspawallet/keys/keys.go#L40`
//! (`type keysFileJSON struct`). Encryption is Argon2id KDF plus
//! XChaCha20-Poly1305 AEAD with the 24-byte nonce prepended to the
//! ciphertext, derived from
//! `https://github.com/kaspanet/kaspad/blob/master/cmd/kaspawallet/keys/keys.go#L378`
//! (`getAEAD` / `decryptMnemonic`).

mod codec;
pub(crate) mod decrypt;
mod encrypt;
mod error;
mod types;

#[cfg(test)]
mod tests;

pub use codec::{read_from_path, read_from_reader, save_to_path};
pub use decrypt::decrypt_mnemonics;
pub use encrypt::encrypt_mnemonic;
pub use error::KeyfileError;
pub use types::{EncryptedMnemonic, KeysFile, LATEST_VERSION};
