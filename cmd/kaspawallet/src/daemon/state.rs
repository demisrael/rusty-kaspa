//! Daemon state: address-set, UTXO snapshot, mempool-excluded
//! UTXOs, used-outpoint expiry tracking, sync progress markers.
//! Mirrors Go `cmd/kaspawallet/daemon/server/server.go@6c1f821f`'s
//! `server` struct minus the kaspad RPC clients (held separately
//! by the sync loop and the transaction-broadcast handlers).
//!
//! The state is held behind an asynchronous `tokio::sync::Mutex`.
//! The Go reference uses a `sync.RWMutex` and acquires it inside
//! synchronous handlers; the async-Rust equivalent matches the
//! lock semantics but yields the executor while contended.
//!
//! Address derivation is performed by a Go-conformant helper
//! (`address_for_wallet_path`) that respects the cosigner-prefix
//! the Go `walletAddressPath` produces for multisig:
//!
//! - single-cosigner: `m/<keychain>/<index>` -- 2 levels off the
//!   keyfile-stored cosigner xpub.
//! - multi-cosigner: `m/<cosigner_index>/<keychain>/<index>` -- 3
//!   levels off each cosigner xpub, combined into an M-of-N
//!   redeem script whose blake2b-256 hash is the P2SH payload.
//!
//! Source: https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/address.go#L116
//! (`walletAddressPath`) and
//! https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/libkaspawallet/keypair.go#L79
//! (`libkaspawallet.Address`).

use std::collections::HashMap;
use std::str::FromStr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use kaspa_addresses::{Address, Prefix as AddressPrefix, Version as AddressVersion};
use kaspa_bip32::{ChildNumber, ExtendedPublicKey};
use kaspa_consensus_core::config::params::{DEVNET_PARAMS, MAINNET_PARAMS, Params, SIMNET_PARAMS, TESTNET_PARAMS};
use kaspa_consensus_core::tx::TransactionOutpoint;
use kaspa_rpc_core::RpcUtxoEntry;
use kaspa_txscript::{multisig_redeem_script, multisig_redeem_script_ecdsa};
use tokio::sync::Mutex;

use crate::keyfile::KeysFile;
use crate::keysource::KeySourceError;

/// Blake2b output length (bytes) used for P2SH script hashing.
/// Matches `kaspa_txscript::pay_to_script_hash_script`.
const SCRIPT_HASH_LEN: usize = 32;

/// Time window after which a previously-attempted-spend outpoint is
/// considered safe to reuse. Matches Go
/// `cmd/kaspawallet/daemon/server/sync.go@6c1f821f::usedOutpointHasExpired`
/// (`time.Minute`).
pub const USED_OUTPOINT_EXPIRY: Duration = Duration::from_secs(60);

/// Coinbase maturity window measured in DAA score units. Mirrors
/// Go's post-Crescendo `coinbaseMaturity = 1000` baked into the
/// daemon at
/// https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/server.go#L100
/// (the Go reference comment notes the value differs from the
/// pre-Crescendo go-kaspad default).
pub const COINBASE_MATURITY: u64 = 1000;

/// Logical key chain a derived address belongs to. The values
/// mirror Go `libkaspawallet.ExternalKeychain = 0` and
/// `InternalKeychain = 1`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum KeyChain {
    External = 0,
    Internal = 1,
}

impl KeyChain {
    /// Hardened-derivation child number for this chain. Both
    /// chains are non-hardened in the Go reference.
    pub fn index(self) -> u32 {
        self as u32
    }
}

/// Wallet-internal address identity: which cosigner stream, which
/// chain, and which leaf index. Mirrors Go
/// `cmd/kaspawallet/daemon/server/common.go::walletAddress`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct WalletAddress {
    pub cosigner_index: u32,
    pub key_chain: KeyChain,
    pub index: u32,
}

/// Map of address-string -> wallet-address identity. Mirrors Go
/// `walletAddressSet`. The keys are the Go-compatible
/// `kaspa:...` / `kaspatest:...` strings the kaspad RPC API
/// consumes.
pub type WalletAddressSet = HashMap<String, WalletAddress>;

/// In-daemon view of a single UTXO. Mirrors Go
/// `cmd/kaspawallet/daemon/server/common.go::walletUTXO`.
#[derive(Debug, Clone)]
pub struct WalletUtxo {
    pub outpoint: TransactionOutpoint,
    pub utxo_entry: RpcUtxoEntry,
    pub address: WalletAddress,
    /// Address string the UTXO was reported for. Cached here so
    /// the per-address-balance handler does not re-encode the
    /// address for every UTXO at lookup time.
    pub address_string: String,
}

/// Sync state of the wallet daemon. The Go reference computes
/// `isSynced()` as
/// `s.nextSyncStartIndex > s.maxUsedIndex() && s.firstSyncDone.Load()`
/// at
/// https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/sync.go#L330.
#[derive(Debug, Clone, Copy)]
pub struct SyncProgress {
    pub first_sync_done: bool,
    pub next_sync_start_index: u32,
    pub last_used_external_index: u32,
    pub last_used_internal_index: u32,
}

impl SyncProgress {
    /// Daemon-side `isSynced` predicate mirroring Go.
    pub fn is_synced(&self) -> bool {
        self.first_sync_done && self.next_sync_start_index > self.max_used_index()
    }

    /// `max(last_used_external_index, last_used_internal_index)`.
    pub fn max_used_index(&self) -> u32 {
        self.last_used_external_index.max(self.last_used_internal_index)
    }

    /// Human-facing summary the daemon emits when an RPC handler
    /// is invoked before `is_synced()` is true. Mirrors Go
    /// `formatSyncStateReport` at
    /// https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/sync.go#L334.
    pub fn format_state_report(&self) -> String {
        let max_used = self.max_used_index().max(self.next_sync_start_index);
        if self.next_sync_start_index < self.max_used_index() {
            let pct = if max_used == 0 { 0.0 } else { f64::from(self.next_sync_start_index) * 100.0 / f64::from(max_used) };
            format!("scanned {} out of {} addresses ({:.2}%)", self.next_sync_start_index, max_used, pct)
        } else {
            "loading the wallet UTXO set".to_owned()
        }
    }
}

/// Snapshot the locked daemon state exposes to RPC handlers. Owned
/// by the caller after acquiring the mutex; the snapshot includes
/// the cosigner-bound keyfile fields the handlers need without
/// requiring the caller to hold the lock across address derivation.
pub struct DaemonState {
    pub keyfile: KeysFile,
    pub address_prefix: AddressPrefix,
    /// Sorted xpubs (lexicographic on the textual form). Mirrors
    /// Go's `sortPublicKeys` step that runs once at keyfile load.
    pub extended_public_keys_sorted: Vec<String>,
    pub address_set: WalletAddressSet,
    /// UTXOs sorted by amount descending; matches Go
    /// `s.utxosSortedByAmount`.
    pub utxos_sorted_by_amount: Vec<WalletUtxo>,
    /// Outpoints excluded because the mempool reports them as
    /// being spent by a transaction sent from this wallet. Mirrors
    /// Go `s.mempoolExcludedUTXOs` keyed by `DomainOutpoint`.
    pub mempool_excluded_utxos: HashMap<TransactionOutpoint, WalletUtxo>,
    /// Outpoints this daemon recently selected for a spending
    /// transaction. Each entry expires after `USED_OUTPOINT_EXPIRY`
    /// past the last completed refresh that observed it.
    pub used_outpoints: HashMap<TransactionOutpoint, Instant>,
    /// Walltime instant at which the most recent successful UTXO
    /// refresh started. Used to expire entries in
    /// `used_outpoints` so a long-running daemon does not leak
    /// memory.
    pub start_time_of_last_completed_refresh: Option<Instant>,
    pub progress: SyncProgress,
}

impl DaemonState {
    /// Construct a fresh state from a loaded keyfile and the
    /// network's address prefix. Address-set, UTXO snapshot, and
    /// mempool-exclusion maps start empty; the sync loop populates
    /// them.
    pub fn new(keyfile: KeysFile, address_prefix: AddressPrefix) -> Self {
        let mut sorted = keyfile.extended_public_keys.clone();
        sorted.sort();
        let progress = SyncProgress {
            first_sync_done: false,
            next_sync_start_index: 0,
            last_used_external_index: keyfile.last_used_external_index,
            last_used_internal_index: keyfile.last_used_internal_index,
        };
        Self {
            keyfile,
            address_prefix,
            extended_public_keys_sorted: sorted,
            address_set: WalletAddressSet::new(),
            utxos_sorted_by_amount: Vec::new(),
            mempool_excluded_utxos: HashMap::new(),
            used_outpoints: HashMap::new(),
            start_time_of_last_completed_refresh: None,
            progress,
        }
    }

    /// Number of cosigners declared by the keyfile.
    pub fn cosigner_count(&self) -> u32 {
        self.extended_public_keys_sorted.len() as u32
    }

    /// Whether this is a multisig keyfile (Go: `isMultisig`).
    pub fn is_multisig(&self) -> bool {
        self.extended_public_keys_sorted.len() > 1
    }

    /// Derive the textual address for the supplied wallet-address
    /// identity. Used by the sync loop to populate the address-set
    /// and by the view handlers (`ShowAddresses`).
    pub fn wallet_address_string(&self, wallet_addr: WalletAddress) -> Result<String, KeySourceError> {
        let address = address_for_wallet_path(
            &self.extended_public_keys_sorted,
            self.keyfile.minimum_signatures,
            self.keyfile.ecdsa,
            self.address_prefix,
            wallet_addr,
        )?;
        Ok(address.to_string())
    }

    /// Derive the textual address for the supplied wallet-address
    /// identity directly (no string allocation for callers that
    /// already need a typed `Address`). Same Go reference as
    /// [`Self::wallet_address_string`].
    pub fn wallet_address(&self, wallet_addr: WalletAddress) -> Result<Address, KeySourceError> {
        address_for_wallet_path(
            &self.extended_public_keys_sorted,
            self.keyfile.minimum_signatures,
            self.keyfile.ecdsa,
            self.address_prefix,
            wallet_addr,
        )
    }

    /// BIP-32 derivation path string for a wallet-address identity.
    /// Mirrors Go `walletAddressPath` at
    /// https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/address.go#L116
    /// -- single-cosigner keyfiles produce `m/<keychain>/<index>`,
    /// multi-cosigner keyfiles produce `m/<cosigner>/<keychain>/<index>`.
    pub fn wallet_address_path(&self, wallet_addr: WalletAddress) -> String {
        if self.is_multisig() {
            format!("m/{}/{}/{}", wallet_addr.cosigner_index, wallet_addr.key_chain.index(), wallet_addr.index)
        } else {
            format!("m/{}/{}", wallet_addr.key_chain.index(), wallet_addr.index)
        }
    }

    /// Spendability predicate. Mirrors Go `isUTXOSpendable` at
    /// https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/balance.go#L70
    /// -- non-coinbase UTXOs are always spendable; coinbase UTXOs
    /// must satisfy `block_daa_score + COINBASE_MATURITY <
    /// virtual_daa_score`.
    pub fn is_utxo_spendable(&self, utxo: &WalletUtxo, virtual_daa_score: u64) -> bool {
        if !utxo.utxo_entry.is_coinbase {
            return true;
        }
        utxo.utxo_entry.block_daa_score + COINBASE_MATURITY < virtual_daa_score
    }

    /// Consensus parameters for the daemon's active network. Used
    /// by the coin-selection / mass-estimation paths the
    /// transaction-construction handlers feed. Mirrors Go's
    /// `s.params` lookup -- the wallet daemon only ever reads
    /// mass coefficients and KIP-9 constants from this value, so a
    /// `&'static Params` reference is sufficient.
    pub fn params(&self) -> &'static Params {
        match self.address_prefix {
            AddressPrefix::Mainnet => &MAINNET_PARAMS,
            AddressPrefix::Testnet => &TESTNET_PARAMS,
            AddressPrefix::Devnet => &DEVNET_PARAMS,
            AddressPrefix::Simnet => &SIMNET_PARAMS,
        }
    }
}

/// Shared, lock-guarded handle to the daemon state. The sync loop
/// and the gRPC service handlers both hold a clone of this
/// `Arc<Mutex<DaemonState>>` and acquire the lock at the boundary
/// of every state-touching operation.
pub type SharedState = Arc<Mutex<DaemonState>>;

/// Construct a `SharedState` wrapper around a fresh `DaemonState`.
pub fn shared(state: DaemonState) -> SharedState {
    Arc::new(Mutex::new(state))
}

/// Go-conformant address derivation for a single wallet-address
/// identity. Single-cosigner keyfiles produce a P2PK (Schnorr or
/// ECDSA per the keyfile's `ecdsa` flag); multi-cosigner keyfiles
/// produce a P2SH whose payload is the blake2b-256 hash of an
/// M-of-N redeem script.
///
/// The path semantics match Go `walletAddressPath` ->
/// `libkaspawallet.Address`:
///
/// - single-cosigner: derive the lone xpub at `<key_chain>/<index>`.
/// - multi-cosigner: derive EACH sorted cosigner xpub at
///   `<cosigner_index>/<key_chain>/<index>`, combine into an M-of-N
///   redeem script (Schnorr 32-byte x-only pubkeys or ECDSA 33-byte
///   compressed pubkeys per the keyfile's `ecdsa` flag), hash the
///   redeem script with blake2b-256, wrap as a P2SH address.
pub fn address_for_wallet_path(
    sorted_xpubs: &[String],
    minimum_signatures: u32,
    ecdsa: bool,
    prefix: AddressPrefix,
    wallet_addr: WalletAddress,
) -> Result<Address, KeySourceError> {
    if sorted_xpubs.is_empty() {
        return Err(KeySourceError::Invalid { field: "publicKeys", reason: "no extended public keys".into() });
    }
    if sorted_xpubs.len() == 1 {
        let pubkey = derive_leaf_pubkey_single_cosigner(&sorted_xpubs[0], wallet_addr.key_chain, wallet_addr.index)?;
        return Ok(if ecdsa {
            Address::new(prefix, AddressVersion::PubKeyECDSA, &pubkey.serialize())
        } else {
            Address::new(prefix, AddressVersion::PubKey, &pubkey.x_only_public_key().0.serialize())
        });
    }

    let required = usize::try_from(minimum_signatures)
        .map_err(|_| KeySourceError::Invalid { field: "minimumSignatures", reason: "exceeds usize".into() })?;
    if minimum_signatures == 0 || required > sorted_xpubs.len() {
        return Err(KeySourceError::Invalid {
            field: "minimumSignatures",
            reason: format!("minimum signatures {minimum_signatures} not in 1..={}", sorted_xpubs.len()),
        });
    }

    let mut leaf_pubkeys = Vec::with_capacity(sorted_xpubs.len());
    for xpub in sorted_xpubs {
        leaf_pubkeys.push(derive_leaf_pubkey_multi_cosigner(
            xpub,
            wallet_addr.cosigner_index,
            wallet_addr.key_chain,
            wallet_addr.index,
        )?);
    }
    let redeem_script = if ecdsa {
        let serialized: Vec<[u8; 33]> = leaf_pubkeys.iter().map(|p| p.serialize()).collect();
        multisig_redeem_script_ecdsa(serialized.iter(), required).map_err(|e| KeySourceError::RedeemScript(e.to_string()))?
    } else {
        let serialized: Vec<[u8; 32]> = leaf_pubkeys.iter().map(|p| p.x_only_public_key().0.serialize()).collect();
        multisig_redeem_script(serialized.iter(), required).map_err(|e| KeySourceError::RedeemScript(e.to_string()))?
    };
    let hash = blake2b_simd::Params::new().hash_length(SCRIPT_HASH_LEN).to_state().update(&redeem_script).finalize();
    Ok(Address::new(prefix, AddressVersion::ScriptHash, hash.as_bytes()))
}

fn derive_leaf_pubkey_single_cosigner(xpub: &str, key_chain: KeyChain, index: u32) -> Result<secp256k1::PublicKey, KeySourceError> {
    let parsed = ExtendedPublicKey::<secp256k1::PublicKey>::from_str(xpub)?;
    let chain_child = parsed.derive_child(ChildNumber::new(key_chain.index(), false)?)?;
    let leaf = chain_child.derive_child(ChildNumber::new(index, false)?)?;
    Ok(*leaf.public_key())
}

fn derive_leaf_pubkey_multi_cosigner(
    xpub: &str,
    cosigner_index: u32,
    key_chain: KeyChain,
    index: u32,
) -> Result<secp256k1::PublicKey, KeySourceError> {
    let parsed = ExtendedPublicKey::<secp256k1::PublicKey>::from_str(xpub)?;
    let cosigner_child = parsed.derive_child(ChildNumber::new(cosigner_index, false)?)?;
    let chain_child = cosigner_child.derive_child(ChildNumber::new(key_chain.index(), false)?)?;
    let leaf = chain_child.derive_child(ChildNumber::new(index, false)?)?;
    Ok(*leaf.public_key())
}
