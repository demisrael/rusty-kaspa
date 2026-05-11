//! Domain types for the legacy Go keyfile format.

use serde::{Deserialize, Serialize};

/// Most up-to-date keyfile format version, mirroring the Go
/// `LastVersion` constant at
/// `https://github.com/kaspanet/kaspad/blob/master/cmd/kaspawallet/keys/keys.go#L29`.
pub const LATEST_VERSION: u32 = 1;

/// Default `numThreads` for v1 keyfiles (matches Go
/// `defaultNumThreads` at
/// `https://github.com/kaspanet/kaspad/blob/master/cmd/kaspawallet/keys/keys.go#L319`).
pub(crate) const DEFAULT_NUM_THREADS: u8 = 8;

/// Argon2id memory cost in KiB (64 MiB), matching the Go
/// `argon2.IDKey(password, salt, 1, 64*1024, threads, 32)` call at
/// `keys.go` `getAEAD`.
pub(crate) const ARGON2_MEMORY_KIB: u32 = 64 * 1024;

/// Argon2id time cost, matching the Go `t = 1` parameter.
pub(crate) const ARGON2_TIME_COST: u32 = 1;

/// Argon2id output length in bytes (XChaCha20-Poly1305 key size).
pub(crate) const ARGON2_OUTPUT_LEN: usize = 32;

/// XChaCha20-Poly1305 nonce size in bytes.
pub(crate) const XCHACHA_NONCE_LEN: usize = 24;

/// Maximum `numThreads` value searched during the v0 brute-force.
pub(crate) const MAX_NUM_THREADS_GUESS: u8 = 255;

/// Wire-level encrypted-mnemonic record. JSON values are hex-encoded
/// byte strings; decoded into raw bytes here.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EncryptedMnemonic {
    /// Nonce (24 bytes) concatenated with the XChaCha20-Poly1305
    /// AEAD output (ciphertext || tag).
    pub cipher: Vec<u8>,
    /// Per-mnemonic Argon2id salt.
    pub salt: Vec<u8>,
}

/// Decoded keyfile. Field names mirror the Go `File` struct in
/// `keys.go`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KeysFile {
    pub version: u32,
    /// `numThreads` is interpreted for v0 (brute-forced) and
    /// constant for v1. For v1 keyfiles the Go reference still
    /// emits this field (default 8); we preserve whatever JSON
    /// supplied so round-trip is exact.
    pub num_threads: u8,
    pub encrypted_mnemonics: Vec<EncryptedMnemonic>,
    pub extended_public_keys: Vec<String>,
    pub minimum_signatures: u32,
    pub cosigner_index: u32,
    pub last_used_external_index: u32,
    pub last_used_internal_index: u32,
    pub ecdsa: bool,
}

/// Wire-format mirror of the Go `keysFileJSON` struct with
/// hex-encoded byte fields and `omitempty` semantics on
/// `numThreads`.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct KeysFileJson {
    pub version: u32,
    #[serde(default, rename = "numThreads", skip_serializing_if = "is_zero_u8")]
    pub num_threads: u8,
    #[serde(rename = "encryptedMnemonics")]
    pub encrypted_mnemonics: Vec<EncryptedMnemonicJson>,
    #[serde(rename = "publicKeys")]
    pub public_keys: Vec<String>,
    #[serde(rename = "minimumSignatures")]
    pub minimum_signatures: u32,
    #[serde(rename = "cosignerIndex")]
    pub cosigner_index: u32,
    #[serde(rename = "lastUsedExternalIndex")]
    pub last_used_external_index: u32,
    #[serde(rename = "lastUsedInternalIndex")]
    pub last_used_internal_index: u32,
    pub ecdsa: bool,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct EncryptedMnemonicJson {
    pub cipher: String,
    pub salt: String,
}

fn is_zero_u8(v: &u8) -> bool {
    *v == 0
}
