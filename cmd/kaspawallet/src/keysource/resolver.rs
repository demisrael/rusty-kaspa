//! Wallet-backend resolver. Reads the `--wallet-backend` flag
//! value and constructs the matching `KeySource` implementation.
//! Only `WalletBackend::Go` resolves successfully in this build;
//! the reserved values return a structured error with the
//! operator-facing wording mandated by the task spec.

use kaspa_addresses::Prefix as AddressPrefix;

use crate::cli::WalletBackend;
use crate::keyfile::KeysFile;

use super::error::ResolveError;
use super::legacy_go::LegacyGoKeyfile;
use super::traits::KeySource;

/// Two key chains in a BIP-32 wallet. Mirrors the Go reference's
/// `ExternalKeychain = 0` / `InternalKeychain = 1` constants
/// (`libkaspawallet/keychains.go`).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KeyChain {
    /// Receiving addresses.
    External,
    /// Change addresses.
    Internal,
}

impl KeyChain {
    pub fn index(self) -> u32 {
        match self {
            KeyChain::External => 0,
            KeyChain::Internal => 1,
        }
    }
}

/// Resolve a backend selection to a concrete `KeySource`
/// implementation. The keyfile + password tuple is consumed only
/// when the resolved backend reads on-disk keyfiles (Go in this
/// build). Hardware-wallet backends (when they land) would accept
/// a different opener tuple; the resolver's surface will grow at
/// that point.
pub fn resolve_backend(
    backend: WalletBackend,
    keyfile: KeysFile,
    password: &[u8],
    address_prefix: AddressPrefix,
) -> Result<Box<dyn KeySource>, ResolveError> {
    match backend {
        WalletBackend::Go => {
            let source = LegacyGoKeyfile::open(keyfile, password, address_prefix)?;
            Ok(Box::new(source))
        }
        WalletBackend::Kdx => Err(ResolveError::BackendNotAvailable { backend: "kdx" }),
        WalletBackend::Tangem => Err(ResolveError::BackendNotAvailable { backend: "tangem" }),
        WalletBackend::Ledger => Err(ResolveError::BackendNotAvailable { backend: "ledger" }),
        WalletBackend::KaspaNg => Err(ResolveError::BackendNotAvailable { backend: "kaspa-ng" }),
    }
}
