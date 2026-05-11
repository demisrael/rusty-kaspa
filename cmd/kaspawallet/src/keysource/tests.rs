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
