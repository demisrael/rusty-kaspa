//! Derivation tests for the legacy Go keyfile backend. Tests
//! against the committed fixtures from `tests/fixtures/`.

use std::path::PathBuf;

use kaspa_addresses::{Prefix, Version};

use crate::cli::WalletBackend;
use crate::keyfile;

use super::resolver::{KeyChain, resolve_backend};
use super::traits::{DerivableKeySource, KeySource};

fn fixture(name: &str) -> PathBuf {
    let mut p = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push(name);
    p
}

fn open_legacy_derivable(name: &str, password: &[u8]) -> super::legacy_go::LegacyGoKeyfile {
    let kf = keyfile::read_from_path(fixture(name)).expect("fixture decodes");
    super::legacy_go::LegacyGoKeyfile::open(kf, password, Prefix::Testnet).expect("opens")
}

#[test]
fn test_resolve_backend_returns_ticket_free_error_for_each_reserved_value() {
    use super::error::ResolveError;
    let kf = keyfile::read_from_path(fixture("legacy_go_v1_singlekey.json")).unwrap();

    for (backend, expected_token) in &[
        (WalletBackend::Kdx, "kdx"),
        (WalletBackend::Tangem, "tangem"),
        (WalletBackend::Ledger, "ledger"),
        (WalletBackend::KaspaNg, "kaspa-ng"),
    ] {
        match resolve_backend(*backend, kf.clone(), b"unused", Prefix::Testnet) {
            Ok(_) => panic!("reserved backend {expected_token} must not resolve in this build"),
            Err(ResolveError::BackendNotAvailable { backend: name }) => {
                assert_eq!(name, *expected_token);
                let msg = format!("{}", ResolveError::BackendNotAvailable { backend: name });
                assert_eq!(msg, format!("wallet backend '{expected_token}' is not available in this build"));
            }
            Err(other) => panic!("expected BackendNotAvailable, got {other:?}"),
        }
    }
}

#[test]
fn test_single_key_schnorr_first_external_address_shape() {
    let src = open_legacy_derivable("legacy_go_v1_singlekey.json", b"test fixture passphrase");
    assert_eq!(src.cosigner_count(), 1);
    assert_eq!(src.extended_public_keys().len(), 1);

    let addr = src.derive_address(KeyChain::External, 0).expect("derives");
    assert_eq!(addr.prefix, Prefix::Testnet, "testnet keyfile must produce kaspatest: addresses");
    assert_eq!(addr.version, Version::PubKey, "Schnorr single-key keyfile produces PubKey-class addresses");
    assert_eq!(addr.payload.len(), 32, "Schnorr x-only pubkey payload is 32 bytes");
}

#[test]
fn test_single_key_external_chain_addresses_are_distinct() {
    let src = open_legacy_derivable("legacy_go_v1_singlekey.json", b"test fixture passphrase");
    let chain = src.chain_addresses(KeyChain::External, 0..5).expect("derives");
    assert_eq!(chain.len(), 5);
    let unique: std::collections::HashSet<_> = chain.iter().collect();
    assert_eq!(unique.len(), 5, "each derived address at a different index must be distinct");
}

#[test]
fn test_single_key_external_vs_internal_diverge() {
    let src = open_legacy_derivable("legacy_go_v1_singlekey.json", b"test fixture passphrase");
    let ext = src.derive_address(KeyChain::External, 0).unwrap();
    let int = src.derive_address(KeyChain::Internal, 0).unwrap();
    assert_ne!(ext, int, "external/0 and internal/0 must derive distinct addresses");
}

#[test]
fn test_ecdsa_keyfile_produces_pubkey_ecdsa_addresses() {
    let src = open_legacy_derivable("legacy_go_v1_ecdsa_singlekey.json", b"ecdsa test passphrase");
    let addr = src.derive_address(KeyChain::External, 0).expect("derives");
    assert_eq!(addr.version, Version::PubKeyECDSA, "ECDSA-mode keyfile produces PubKeyECDSA-class addresses");
    assert_eq!(addr.payload.len(), 33, "ECDSA pubkey payload is 33 bytes (compressed)");
}

#[test]
fn test_multisig_2of3_address_is_script_hash() {
    let src = open_legacy_derivable("legacy_go_v1_multisig_2of3.json", b"multisig test passphrase");
    assert_eq!(src.cosigner_count(), 3);
    assert_eq!(src.extended_public_keys().len(), 3);
    let addr = src.derive_address(KeyChain::External, 0).expect("derives multisig");
    assert_eq!(addr.version, Version::ScriptHash, "multisig keyfile produces ScriptHash-class addresses");
    assert_eq!(addr.payload.len(), 32, "blake2b-256 hash payload is 32 bytes");
}

#[test]
fn test_multisig_xpubs_are_sorted_internally() {
    let src = open_legacy_derivable("legacy_go_v1_multisig_2of3.json", b"multisig test passphrase");
    let xpubs = src.extended_public_keys();
    let mut sorted = xpubs.to_vec();
    sorted.sort();
    assert_eq!(xpubs, sorted.as_slice(), "extended_public_keys must be lexicographically sorted");
}

#[test]
fn test_multisig_chain_addresses_distinct() {
    let src = open_legacy_derivable("legacy_go_v1_multisig_2of3.json", b"multisig test passphrase");
    let chain = src.chain_addresses(KeyChain::External, 0..3).expect("derives");
    assert_eq!(chain.len(), 3);
    let unique: std::collections::HashSet<_> = chain.iter().collect();
    assert_eq!(unique.len(), 3);
}

#[test]
fn test_change_address_advances_internal_index() {
    let src = open_legacy_derivable("legacy_go_v1_singlekey.json", b"test fixture passphrase");
    let first = src.change_address().unwrap();
    let second = src.change_address().unwrap();
    assert_ne!(first, second, "successive change_address calls must advance the chain pointer");
    // The single-key chain places `internal/0` at the first call. The second
    // call must place `internal/1`, which must match an explicit derivation
    // at idx 1.
    let explicit = src.derive_address(KeyChain::Internal, 1).unwrap();
    assert_eq!(second, explicit);
}

#[test]
fn test_receiving_address_with_explicit_index_is_deterministic() {
    let src = open_legacy_derivable("legacy_go_v1_singlekey.json", b"test fixture passphrase");
    let a = src.receiving_address(Some(7)).unwrap();
    let b = src.receiving_address(Some(7)).unwrap();
    assert_eq!(a, b, "explicit-index receiving_address must be deterministic");
    // Explicit index must NOT advance the pointer; subsequent `None` call
    // returns the pointer's current value, not the explicit index + 1.
    let next_implicit = src.receiving_address(None).unwrap();
    let next_explicit = src.derive_address(KeyChain::External, 0).unwrap();
    assert_eq!(next_implicit, next_explicit, "implicit-index call must start at the pointer's value, not the explicit index");
}

#[test]
fn test_resolve_via_go_backend_returns_working_keysource() {
    let kf = keyfile::read_from_path(fixture("legacy_go_v1_singlekey.json")).unwrap();
    let src = resolve_backend(WalletBackend::Go, kf, b"test fixture passphrase", Prefix::Testnet).expect("go backend resolves");
    assert_eq!(src.cosigner_count(), 1);
    let addr = src.receiving_address(Some(0)).unwrap();
    assert_eq!(addr.prefix, Prefix::Testnet);
    assert_eq!(addr.version, Version::PubKey);
}

#[test]
fn test_resolve_with_wrong_password_propagates_mac_failure() {
    let kf = keyfile::read_from_path(fixture("legacy_go_v1_singlekey.json")).unwrap();
    match resolve_backend(WalletBackend::Go, kf, b"wrong", Prefix::Testnet) {
        Ok(_) => panic!("wrong password must not resolve"),
        Err(err) => {
            let s = format!("{err}");
            assert!(s.contains("authentication failed") || s.contains("keyfile"), "wrong-password resolver error must propagate: {s}");
        }
    }
}

// `sign_for` unit tests. Cover the 65-byte wire shape, the
// cosigner_idx / msg-length error paths, the Schnorr-vs-ECDSA
// dispatch, and the ECDSA RFC-6979 determinism property.

/// Single-cosigner Schnorr-key fixture's BIP-43 cosigner prefix.
/// Used to derive the leaf x-only pubkey for in-test signature
/// verification.
const SINGLE_SIG_COSIGNER_PREFIX: &str = "m/44'/111111'/0'";

/// Multisig 2-of-3 fixture's BIP-43 cosigner prefix.
const MULTISIG_COSIGNER_PREFIX: &str = "m/45'/111111'/0'";

/// Test relative path used across sign_for tests.
const TEST_LEAF_RELATIVE_PATH: &str = "m/0/0";

/// Test sighash digest: 32 bytes covering ASCII-printable values 0..32.
const TEST_SIGHASH: [u8; 32] = [
    0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15,
    0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20,
];

/// `SIG_HASH_ALL` byte value (`SigHashType::All.to_u8()` in the
/// kaspa-consensus-core enum). Mirrored here to keep the assertion
/// readable without a kaspa-consensus-core import in the test
/// module.
const SIG_HASH_ALL_BYTE: u8 = 0x01;

/// Expected signature-plus-sighash-type blob length: 64-byte raw
/// signature + 1-byte sighash type.
const EXPECTED_SIG_BLOB_LEN: usize = 65;

fn derive_leaf_xonly_pubkey(mnemonic_phrase: &str, cosigner_prefix: &str, relative: &str) -> secp256k1::XOnlyPublicKey {
    use std::str::FromStr;

    use kaspa_bip32::{DerivationPath, ExtendedPrivateKey, Language, Mnemonic, SecretKey};

    let mnemonic = Mnemonic::new(mnemonic_phrase, Language::English).expect("mnemonic parses");
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::<SecretKey>::new(seed.as_bytes()).expect("master xpriv");
    let prefix_path = DerivationPath::from_str(cosigner_prefix).expect("cosigner-prefix path parses");
    let relative_path = DerivationPath::from_str(relative).expect("relative path parses");
    let leaf = master.derive_path(&prefix_path).expect("cosigner walk").derive_path(&relative_path).expect("relative walk");
    let secret = *leaf.private_key();
    let keypair = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &secret);
    keypair.x_only_public_key().0
}

fn derive_leaf_pubkey(mnemonic_phrase: &str, cosigner_prefix: &str, relative: &str) -> secp256k1::PublicKey {
    use std::str::FromStr;

    use kaspa_bip32::{DerivationPath, ExtendedPrivateKey, Language, Mnemonic, SecretKey};

    let mnemonic = Mnemonic::new(mnemonic_phrase, Language::English).expect("mnemonic parses");
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::<SecretKey>::new(seed.as_bytes()).expect("master xpriv");
    let prefix_path = DerivationPath::from_str(cosigner_prefix).expect("cosigner-prefix path parses");
    let relative_path = DerivationPath::from_str(relative).expect("relative path parses");
    let leaf = master.derive_path(&prefix_path).expect("cosigner walk").derive_path(&relative_path).expect("relative walk");
    let secret = *leaf.private_key();
    secp256k1::PublicKey::from_secret_key(secp256k1::SECP256K1, &secret)
}

fn singlekey_mnemonic() -> String {
    let kf = keyfile::read_from_path(fixture("legacy_go_v1_singlekey.json")).unwrap();
    let decrypted = keyfile::decrypt_mnemonics(&kf, b"test fixture passphrase").expect("decrypt");
    decrypted[0].clone()
}

fn ecdsa_singlekey_mnemonic() -> String {
    let kf = keyfile::read_from_path(fixture("legacy_go_v1_ecdsa_singlekey.json")).unwrap();
    let decrypted = keyfile::decrypt_mnemonics(&kf, b"ecdsa test passphrase").expect("decrypt");
    decrypted[0].clone()
}

#[test]
fn test_sign_for_single_key_schnorr_returns_65_byte_blob_with_sighash_type() {
    let src = open_legacy_derivable("legacy_go_v1_singlekey.json", b"test fixture passphrase");
    let blob = src.sign_for(0, TEST_LEAF_RELATIVE_PATH, &TEST_SIGHASH).expect("sign_for succeeds");
    assert_eq!(blob.len(), EXPECTED_SIG_BLOB_LEN, "Schnorr sig-with-hash-type blob is exactly 65 bytes");
    assert_eq!(*blob.last().unwrap(), SIG_HASH_ALL_BYTE, "trailing byte must be SIG_HASH_ALL");
}

#[test]
fn test_sign_for_single_key_ecdsa_returns_65_byte_blob_with_sighash_type() {
    let src = open_legacy_derivable("legacy_go_v1_ecdsa_singlekey.json", b"ecdsa test passphrase");
    let blob = src.sign_for(0, TEST_LEAF_RELATIVE_PATH, &TEST_SIGHASH).expect("sign_for succeeds");
    assert_eq!(blob.len(), EXPECTED_SIG_BLOB_LEN, "ECDSA compact sig-with-hash-type blob is exactly 65 bytes");
    assert_eq!(*blob.last().unwrap(), SIG_HASH_ALL_BYTE, "trailing byte must be SIG_HASH_ALL");
}

#[test]
fn test_sign_for_rejects_out_of_range_cosigner_idx() {
    let src = open_legacy_derivable("legacy_go_v1_singlekey.json", b"test fixture passphrase");
    let err =
        src.sign_for(1, TEST_LEAF_RELATIVE_PATH, &TEST_SIGHASH).expect_err("single-cosigner keyfile must reject cosigner_idx >= 1");
    let msg = format!("{err}");
    assert!(msg.contains("cosigner_idx"), "error must name the offending field: {msg}");
}

#[test]
fn test_sign_for_rejects_short_sighash() {
    let src = open_legacy_derivable("legacy_go_v1_singlekey.json", b"test fixture passphrase");
    let short = [0u8; 16];
    let err = src.sign_for(0, TEST_LEAF_RELATIVE_PATH, &short).expect_err("16-byte digest must be rejected");
    let msg = format!("{err}");
    assert!(msg.contains("32-byte sighash") || msg.contains("msg"), "error must surface the sighash-length mismatch: {msg}");
}

#[test]
fn test_sign_for_schnorr_signature_verifies_under_derived_xonly_pubkey() {
    let src = open_legacy_derivable("legacy_go_v1_singlekey.json", b"test fixture passphrase");
    let blob = src.sign_for(0, TEST_LEAF_RELATIVE_PATH, &TEST_SIGHASH).expect("sign_for succeeds");
    let sig_bytes: &[u8] = &blob[..64];
    let sig = secp256k1::schnorr::Signature::from_slice(sig_bytes).expect("64-byte schnorr signature");

    let mnemonic = singlekey_mnemonic();
    let xonly = derive_leaf_xonly_pubkey(&mnemonic, SINGLE_SIG_COSIGNER_PREFIX, TEST_LEAF_RELATIVE_PATH);
    let msg = secp256k1::Message::from_digest_slice(&TEST_SIGHASH).expect("digest");

    secp256k1::SECP256K1
        .verify_schnorr(&sig, &msg, &xonly)
        .expect("Schnorr signature must verify under the derived leaf x-only pubkey");
}

#[test]
fn test_sign_for_ecdsa_signature_verifies_under_derived_pubkey() {
    let src = open_legacy_derivable("legacy_go_v1_ecdsa_singlekey.json", b"ecdsa test passphrase");
    let blob = src.sign_for(0, TEST_LEAF_RELATIVE_PATH, &TEST_SIGHASH).expect("sign_for succeeds");
    let sig_bytes: &[u8] = &blob[..64];
    let sig = secp256k1::ecdsa::Signature::from_compact(sig_bytes).expect("64-byte compact ECDSA signature");

    let mnemonic = ecdsa_singlekey_mnemonic();
    let pubkey = derive_leaf_pubkey(&mnemonic, SINGLE_SIG_COSIGNER_PREFIX, TEST_LEAF_RELATIVE_PATH);
    let msg = secp256k1::Message::from_digest_slice(&TEST_SIGHASH).expect("digest");

    secp256k1::SECP256K1.verify_ecdsa(&msg, &sig, &pubkey).expect("ECDSA signature must verify under the derived leaf pubkey");
}

#[test]
fn test_sign_for_ecdsa_signature_is_deterministic_rfc6979() {
    let src = open_legacy_derivable("legacy_go_v1_ecdsa_singlekey.json", b"ecdsa test passphrase");
    let a = src.sign_for(0, TEST_LEAF_RELATIVE_PATH, &TEST_SIGHASH).expect("first signing succeeds");
    let b = src.sign_for(0, TEST_LEAF_RELATIVE_PATH, &TEST_SIGHASH).expect("second signing succeeds");
    assert_eq!(a, b, "ECDSA sign over RFC 6979 deterministic nonces must be byte-identical across invocations on the same (key, msg)");
}

#[test]
fn test_sign_for_multisig_signs_with_specified_cosigner() {
    let src = open_legacy_derivable("legacy_go_v1_multisig_2of3.json", b"multisig test passphrase");
    // The 2-of-3 fixture holds 3 mnemonics. Signing with each cosigner index
    // must succeed and the resulting signature must verify under the
    // corresponding cosigner's derived leaf x-only pubkey.
    let kf = keyfile::read_from_path(fixture("legacy_go_v1_multisig_2of3.json")).unwrap();
    let decrypted = keyfile::decrypt_mnemonics(&kf, b"multisig test passphrase").expect("decrypt");
    for (cosigner_idx, mnemonic) in decrypted.iter().enumerate() {
        let cosigner_u32 = u32::try_from(cosigner_idx).unwrap();
        let blob =
            src.sign_for(cosigner_u32, TEST_LEAF_RELATIVE_PATH, &TEST_SIGHASH).expect("sign_for succeeds for valid cosigner_idx");
        assert_eq!(blob.len(), EXPECTED_SIG_BLOB_LEN);
        assert_eq!(*blob.last().unwrap(), SIG_HASH_ALL_BYTE);

        let sig_bytes: &[u8] = &blob[..64];
        let sig = secp256k1::schnorr::Signature::from_slice(sig_bytes).expect("schnorr signature");
        let xonly = derive_leaf_xonly_pubkey(mnemonic, MULTISIG_COSIGNER_PREFIX, TEST_LEAF_RELATIVE_PATH);
        let msg = secp256k1::Message::from_digest_slice(&TEST_SIGHASH).expect("digest");
        secp256k1::SECP256K1
            .verify_schnorr(&sig, &msg, &xonly)
            .expect("multisig cosigner signature must verify under that cosigner's derived leaf x-only pubkey");
    }
}
