//! Wallet daemon sync loop.
//!
//! Ports Go `cmd/kaspawallet/daemon/server/sync.go@6c1f821f` to
//! async Rust. The loop runs on a ~1-second ticker and performs:
//!
//! 1. Initial scan -- `collect_recent_addresses` walks the address
//!    space in 1000-index batches starting from cosigner-index 0
//!    until it exceeds `max_used_index + 1000`. Addresses that
//!    return a positive balance from kaspad are added to the
//!    address-set and their indices are recorded as
//!    `last_used_*_index`.
//! 2. Initial UTXO refresh -- `refresh_utxos` calls
//!    `GetMempoolEntriesByAddresses` (to capture mempool-spent
//!    outpoints) then `GetUTXOsByAddresses` (to capture the full
//!    UTXO set) and updates the daemon's amount-sorted snapshot.
//! 3. Sets `first_sync_done = true`. The view RPCs unblock at this
//!    point.
//! 4. On every tick (or on every signal through the
//!    `force_sync_tx` channel): `collect_far_addresses` -- walks
//!    an additional 100 indices past the current `next_sync_start_
//!    index` so newly-funded addresses past the daemon's known
//!    range are discovered. Then `collect_recent_addresses` and
//!    `refresh_utxos` again.
//!
//! The loop terminates cleanly when its `shutdown` future
//! resolves; the future is driven by the daemon's `Notify` handle
//! so SIGINT or an in-process `Shutdown` RPC stops the loop at
//! the next yield point.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::{Duration, Instant};

use kaspa_consensus_core::tx::TransactionOutpoint;
use kaspa_rpc_core::{
    RpcAddress, RpcBalancesByAddressesEntry, RpcMempoolEntryByAddress, RpcTransactionOutpoint, RpcUtxosByAddressesEntry,
};
use tokio::sync::Notify;
use tokio::time::{Interval, interval, sleep};

use super::error::DaemonError;
use super::kaspad::KaspadFacade;
use super::state::{KeyChain, SharedState, WalletAddress, WalletAddressSet, WalletUtxo};

/// Indices to query per call into `collect_far_addresses`. Matches
/// Go `numIndexesToQueryForFarAddresses = 100`.
pub const FAR_BATCH_SIZE: u32 = 100;

/// Indices to query per call into `collect_recent_addresses`.
/// Matches Go `numIndexesToQueryForRecentAddresses = 1000`.
pub const RECENT_BATCH_SIZE: u32 = 1000;

/// Sync-loop tick interval. Matches Go's 1-second ticker.
pub const SYNC_TICK: Duration = Duration::from_secs(1);

/// Driver for the background sync work. Owns the kaspad facade
/// and the shared state handle; runs to completion when the
/// shutdown notification fires.
pub struct SyncLoop {
    state: SharedState,
    kaspad: Arc<dyn KaspadFacade>,
    shutdown: Arc<Notify>,
    force_sync: Arc<Notify>,
}

impl SyncLoop {
    /// Construct a sync-loop driver. The caller retains a clone
    /// of the shutdown notification so the daemon runtime can fire
    /// it on SIGINT or `Shutdown` RPC. `force_sync` is the
    /// in-daemon "force refresh" channel; the heavier RPCs poke
    /// it after mutating state so a follow-on refresh runs
    /// without waiting for the next tick.
    pub fn new(state: SharedState, kaspad: Arc<dyn KaspadFacade>, shutdown: Arc<Notify>, force_sync: Arc<Notify>) -> Self {
        Self { state, kaspad, shutdown, force_sync }
    }

    /// Run the sync loop to completion. Returns when the shutdown
    /// future fires or when an unrecoverable kaspad RPC error
    /// surfaces during the initial sync.
    pub async fn run(self) -> Result<(), DaemonError> {
        self.collect_recent_addresses().await?;
        self.refresh_utxos().await?;

        {
            let mut state = self.state.lock().await;
            state.progress.first_sync_done = true;
        }

        let mut ticker = interval(SYNC_TICK);
        ticker.tick().await; // consume the immediate tick

        loop {
            let next_tick = async {
                tick_or_force(&mut ticker, self.force_sync.as_ref()).await;
            };
            tokio::select! {
                _ = self.shutdown.notified() => return Ok(()),
                _ = next_tick => {
                    self.sync().await?;
                }
            }
        }
    }

    /// One sync iteration: extend the far-address range, rescan
    /// recent addresses to catch any new balances, refresh the
    /// UTXO snapshot. Public so unit tests can drive a single
    /// step with a mock facade.
    pub async fn sync(&self) -> Result<(), DaemonError> {
        self.collect_far_addresses().await?;
        self.collect_recent_addresses().await?;
        self.refresh_utxos().await
    }

    async fn collect_recent_addresses(&self) -> Result<(), DaemonError> {
        let mut index: u32 = 0;
        loop {
            self.collect_addresses(index, index.saturating_add(RECENT_BATCH_SIZE)).await?;
            // Re-read max-used under the lock so a positive
            // balance discovered in the current batch extends the
            // scan window before the loop condition is checked.
            let max_used = self.state.lock().await.progress.max_used_index();
            let next = index.saturating_add(RECENT_BATCH_SIZE);
            if next >= max_used.saturating_add(RECENT_BATCH_SIZE) {
                index = next;
                break;
            }
            index = next;
        }
        let mut state = self.state.lock().await;
        if index > state.progress.next_sync_start_index {
            state.progress.next_sync_start_index = index;
        }
        Ok(())
    }

    async fn collect_far_addresses(&self) -> Result<(), DaemonError> {
        let start = self.state.lock().await.progress.next_sync_start_index;
        let end = start.saturating_add(FAR_BATCH_SIZE);
        self.collect_addresses(start, end).await?;
        let mut state = self.state.lock().await;
        state.progress.next_sync_start_index = state.progress.next_sync_start_index.saturating_add(FAR_BATCH_SIZE);
        Ok(())
    }

    async fn collect_addresses(&self, start: u32, end: u32) -> Result<(), DaemonError> {
        let (requested_set, addresses): (WalletAddressSet, Vec<RpcAddress>) = self.addresses_to_query(start, end).await?;
        if addresses.is_empty() {
            return Ok(());
        }
        let balances = self.kaspad.get_balances_by_addresses(addresses).await?;
        self.update_addresses_and_last_used(requested_set, balances).await
    }

    async fn addresses_to_query(&self, start: u32, end: u32) -> Result<(WalletAddressSet, Vec<RpcAddress>), DaemonError> {
        // Snapshot the keyfile-derived inputs under the lock,
        // then drop the lock before doing the (potentially many)
        // BIP-32 derivations so the service handlers stay
        // unblocked while the sync loop computes addresses.
        let state = self.state.lock().await;
        let cosigner_count = state.cosigner_count();
        let sorted_xpubs = state.extended_public_keys_sorted.clone();
        let min_sigs = state.keyfile.minimum_signatures;
        let ecdsa = state.keyfile.ecdsa;
        let prefix = state.address_prefix;
        drop(state);

        let mut requested = WalletAddressSet::new();
        let mut addresses = Vec::new();
        for index in start..end {
            for cosigner_index in 0..cosigner_count {
                for &key_chain in &[KeyChain::External, KeyChain::Internal] {
                    let wallet_addr = WalletAddress { cosigner_index, key_chain, index };
                    let address = super::state::address_for_wallet_path(&sorted_xpubs, min_sigs, ecdsa, prefix, wallet_addr)
                        .map_err(|e| DaemonError::Runtime(format!("address derivation failed: {e}")))?;
                    let address_string = address.to_string();
                    requested.insert(address_string, wallet_addr);
                    addresses.push(address);
                }
            }
        }
        Ok((requested, addresses))
    }

    async fn update_addresses_and_last_used(
        &self,
        requested: WalletAddressSet,
        balances: Vec<RpcBalancesByAddressesEntry>,
    ) -> Result<(), DaemonError> {
        let mut state = self.state.lock().await;
        let mut last_used_external = state.progress.last_used_external_index;
        let mut last_used_internal = state.progress.last_used_internal_index;
        for entry in balances {
            let address_string = entry.address.to_string();
            let wallet_addr = requested.get(&address_string).copied().ok_or_else(|| {
                DaemonError::Runtime(format!("kaspad returned address {address_string} that was not in the request set"))
            })?;
            if entry.balance.unwrap_or(0) == 0 {
                continue;
            }
            state.address_set.insert(address_string, wallet_addr);
            match wallet_addr.key_chain {
                KeyChain::External => {
                    if wallet_addr.index > last_used_external {
                        last_used_external = wallet_addr.index;
                    }
                }
                KeyChain::Internal => {
                    if wallet_addr.index > last_used_internal {
                        last_used_internal = wallet_addr.index;
                    }
                }
            }
        }
        state.progress.last_used_external_index = last_used_external;
        state.progress.last_used_internal_index = last_used_internal;
        state.keyfile.last_used_external_index = last_used_external;
        state.keyfile.last_used_internal_index = last_used_internal;
        Ok(())
    }

    async fn refresh_utxos(&self) -> Result<(), DaemonError> {
        let refresh_start = Instant::now();
        let (addresses_for_rpc, address_lookup): (Vec<RpcAddress>, HashMap<String, WalletAddress>) = {
            let state = self.state.lock().await;
            let mut for_rpc = Vec::with_capacity(state.address_set.len());
            let mut lookup = HashMap::with_capacity(state.address_set.len());
            for (s, w) in state.address_set.iter() {
                let address = RpcAddress::try_from(s.as_str())
                    .map_err(|e| DaemonError::Runtime(format!("address parse failed for '{s}': {e}")))?;
                for_rpc.push(address);
                lookup.insert(s.clone(), *w);
            }
            (for_rpc, lookup)
        };
        if addresses_for_rpc.is_empty() {
            let mut state = self.state.lock().await;
            state.start_time_of_last_completed_refresh = Some(refresh_start);
            state.utxos_sorted_by_amount.clear();
            state.mempool_excluded_utxos.clear();
            return Ok(());
        }
        // Mempool first, then UTXO snapshot -- matches Go's
        // ordering comment about avoiding a window where an
        // output is spent in the mempool but still appears in the
        // UTXO response.
        let mempool = self.kaspad.get_mempool_entries_by_addresses(addresses_for_rpc.clone(), true, true).await?;
        let utxos = self.kaspad.get_utxos_by_addresses(addresses_for_rpc).await?;
        self.update_utxo_set(utxos, mempool, address_lookup, refresh_start).await
    }

    async fn update_utxo_set(
        &self,
        entries: Vec<RpcUtxosByAddressesEntry>,
        mempool: Vec<RpcMempoolEntryByAddress>,
        address_lookup: HashMap<String, WalletAddress>,
        refresh_start: Instant,
    ) -> Result<(), DaemonError> {
        let exclude: HashSet<TransactionOutpoint> = mempool
            .into_iter()
            .flat_map(|entry_by_addr| entry_by_addr.sending.into_iter())
            .flat_map(|mempool_entry| {
                mempool_entry.transaction.inputs.into_iter().map(|input| TransactionOutpoint::from(input.previous_outpoint))
            })
            .collect();

        let mut available = Vec::with_capacity(entries.len());
        let mut excluded = HashMap::new();
        for entry in entries {
            let outpoint = TransactionOutpoint::from(entry.outpoint);
            let address_string = entry
                .address
                .as_ref()
                .map(|a| a.to_string())
                .ok_or_else(|| DaemonError::Runtime("kaspad UTXO entry missing address".to_owned()))?;
            let wallet_addr = address_lookup
                .get(&address_string)
                .copied()
                .ok_or_else(|| DaemonError::Runtime(format!("kaspad returned UTXO for unrequested address '{address_string}'")))?;
            let utxo =
                WalletUtxo { outpoint, utxo_entry: entry.utxo_entry, address: wallet_addr, address_string: address_string.clone() };
            if exclude.contains(&outpoint) {
                excluded.insert(outpoint, utxo);
            } else {
                available.push(utxo);
            }
        }
        // Unstable sort to mirror Go `sync.go:279`'s
        // `sort.Slice(utxos, func(i, j int) bool { return ... })`
        // semantics. Go's `sort.Slice` is unstable (pdqsort variant);
        // Rust's stable `sort_by` would leave equal-amount UTXOs in
        // kaspad-RPC insertion order, which can diverge from Go on
        // tie-broken coinbase outputs. Cross-binary byte-identity
        // hinges on the two binaries selecting the same UTXOs on a
        // shared wallet snapshot.
        available.sort_unstable_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));

        let mut state = self.state.lock().await;
        state.start_time_of_last_completed_refresh = Some(refresh_start);
        state.utxos_sorted_by_amount = available;
        state.mempool_excluded_utxos = excluded;
        state.used_outpoints.retain(|_, broadcast_time| !used_outpoint_has_expired(*broadcast_time, refresh_start));
        Ok(())
    }
}

/// Internal helper: an outpoint is reusable once an entire UTXO
/// refresh started after `USED_OUTPOINT_EXPIRY` past the
/// broadcast time. Mirrors Go's `usedOutpointHasExpired`.
fn used_outpoint_has_expired(broadcast_time: Instant, refresh_start: Instant) -> bool {
    refresh_start >= broadcast_time + super::state::USED_OUTPOINT_EXPIRY
}

async fn tick_or_force(ticker: &mut Interval, force_sync: &Notify) {
    tokio::select! {
        _ = ticker.tick() => {},
        _ = force_sync.notified() => {
            // After a forced sync, briefly yield so the next tick
            // does not double-fire immediately when the ticker
            // catches up.
            sleep(Duration::from_millis(10)).await;
        },
    }
}

/// Convert an `RpcTransactionOutpoint` back to a domain
/// `TransactionOutpoint`. Re-exported for test scaffolding.
pub fn outpoint_from_rpc(op: RpcTransactionOutpoint) -> TransactionOutpoint {
    TransactionOutpoint::from(op)
}
