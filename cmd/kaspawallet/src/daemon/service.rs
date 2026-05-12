//! `KaspawalletdSvc` -- implementation of the generated
//! `kaspawalletd::kaspawalletd_server::Kaspawalletd` trait.
//!
//! Three classes of handler land here:
//!
//! 1. Handlers that depend only on the daemon's own state and do
//!    not require a synced UTXO snapshot (`GetVersion`,
//!    `Shutdown`).
//! 2. Handlers that depend on the daemon's address-set and UTXO
//!    snapshot (`ShowAddresses`, `GetBalance`,
//!    `GetExternalSpendableUTXOs`). Gated on
//!    `progress.is_synced()`; unsynced calls return
//!    `Status::failed_precondition("wallet daemon is not synced
//!    yet, <state report>")`.
//! 3. Handlers that mutate the keyfile (`NewAddress`) or construct
//!    / sign / broadcast transactions (`CreateUnsignedTransactions`,
//!    `Send`, `Sign`, `Broadcast`, `BroadcastReplacement`,
//!    `BumpFee`). All gate on `state_or_unsynced` and on the
//!    configured kaspad facade. The composition trio
//!    (`CreateUnsignedTransactions`, `Send`, `BumpFee`) routes
//!    through the same coin-selection + change-address +
//!    serialization helpers, so the unsigned-PST wire bytes are
//!    consistent across the standalone and daemon code paths.

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;
use std::time::Instant;

use kaspa_addresses::Address;
use kaspa_consensus_core::tx::{Transaction, TransactionOutpoint};
use kaspa_rpc_core::{RpcTransaction, RpcTransactionId};
use kaspa_txscript::extract_script_pub_key_address;
use tokio::sync::{MutexGuard, Notify};
use tonic::{Request, Response, Status};
use zeroize::Zeroizing;

use super::kaspad::KaspadFacade;
use super::pb::fee_policy::FeePolicy as FeePolicyOneof;
use super::pb::kaspawalletd_server::Kaspawalletd;
use super::pb::{
    AddressBalances, BroadcastRequest, BroadcastResponse, BumpFeeRequest, BumpFeeResponse, CreateUnsignedTransactionsRequest,
    CreateUnsignedTransactionsResponse, FeePolicy, GetBalanceRequest, GetBalanceResponse, GetExternalSpendableUtxOsRequest,
    GetExternalSpendableUtxOsResponse, GetVersionRequest, GetVersionResponse, NewAddressRequest, NewAddressResponse, Outpoint,
    ScriptPublicKey, SendRequest, SendResponse, ShowAddressesRequest, ShowAddressesResponse, ShutdownRequest, ShutdownResponse,
    SignRequest, SignResponse, UtxoEntry, UtxosByAddressesEntry,
};
use super::state::{DaemonState, KeyChain, SharedState, WalletAddress};
use crate::coinsel::{Selection, WalletConfig, maybe_auto_compound_transaction, select_utxos};
use crate::keyfile::{self, KeysFile};
use crate::serialization;
use crate::sign::{extract_transaction, sign_pst_ecdsa_with_mnemonic, sign_pst_schnorr_with_mnemonic};
use crate::transaction::{Payment, Utxo as LibUtxo, create_unsigned_transaction};

/// Minimum mempool-accepted fee rate (sompi/gram).
const MIN_FEE_RATE: f64 = 1.0;

/// Sompi-per-kaspa exchange constant. Used as the default
/// `max_fee` cap (1 KAS) when the request omits a fee policy
/// entirely.
const SOMPI_PER_KASPA: u64 = 100_000_000;

pub struct KaspawalletdSvc {
    version: String,
    shutdown: Arc<Notify>,
    state: Option<SharedState>,
    kaspad: Option<Arc<dyn KaspadFacade>>,
    force_sync: Option<Arc<Notify>>,
    /// On-disk path the daemon was started against. The mutating
    /// handlers (`NewAddress`, `CreateUnsignedTransactions`,
    /// `Send`, `BumpFee`) persist the keyfile back to this path
    /// after bumping `last_used_*_index`.
    keysfile_path: Option<PathBuf>,
}

impl KaspawalletdSvc {
    /// Construct a service bound to a shared daemon state, a kaspad
    /// facade, a force-sync handle, and the on-disk keyfile path
    /// that mutating handlers persist updates to. Used by the
    /// production daemon and any integration test that wires real
    /// or mocked state.
    pub fn new(
        version: impl Into<String>,
        shutdown: Arc<Notify>,
        state: SharedState,
        kaspad: Arc<dyn KaspadFacade>,
        force_sync: Arc<Notify>,
        keysfile_path: PathBuf,
    ) -> Self {
        Self {
            version: version.into(),
            shutdown,
            state: Some(state),
            kaspad: Some(kaspad),
            force_sync: Some(force_sync),
            keysfile_path: Some(keysfile_path),
        }
    }

    /// Construct a service with no shared state, kaspad, or
    /// keyfile-path. Used by the `daemon_smoke` integration test
    /// that exercises only `GetVersion` + `Shutdown` and asserts the
    /// heavier RPCs return `FailedPrecondition` over the wire.
    pub fn without_state(version: impl Into<String>, shutdown: Arc<Notify>) -> Self {
        Self { version: version.into(), shutdown, state: None, kaspad: None, force_sync: None, keysfile_path: None }
    }

    /// Test-only constructor: state + mock kaspad facade + force-sync
    /// handle + keyfile path. Same wiring as `new`, but the type
    /// name records the intent at call sites.
    #[cfg(test)]
    pub fn with_mocks(
        version: impl Into<String>,
        shutdown: Arc<Notify>,
        state: SharedState,
        kaspad: Arc<dyn KaspadFacade>,
        force_sync: Arc<Notify>,
        keysfile_path: PathBuf,
    ) -> Self {
        Self::new(version, shutdown, state, kaspad, force_sync, keysfile_path)
    }

    /// Test / introspection helper -- returns the configured
    /// version string. Not part of the gRPC surface.
    pub fn version(&self) -> &str {
        &self.version
    }

    /// Acquire the shared state or return a `FailedPrecondition`
    /// status when none is wired (test mode without sync).
    async fn state_or_unsynced(&self) -> Result<MutexGuard<'_, DaemonState>, Status> {
        let Some(state) = self.state.as_ref() else {
            return Err(Status::failed_precondition("wallet daemon is not synced yet, loading the wallet UTXO set"));
        };
        let guard = state.lock().await;
        if !guard.progress.is_synced() {
            let report = guard.progress.format_state_report();
            return Err(Status::failed_precondition(format!("wallet daemon is not synced yet, {report}")));
        }
        Ok(guard)
    }

    /// Borrow the kaspad facade or return `FailedPrecondition`.
    fn kaspad_or_unsynced(&self) -> Result<&Arc<dyn KaspadFacade>, Status> {
        self.kaspad.as_ref().ok_or_else(|| Status::failed_precondition("wallet daemon is not synced yet, loading the wallet UTXO set"))
    }

    /// Borrow the configured keyfile path or return `FailedPrecondition`.
    fn keysfile_path_or_unsynced(&self) -> Result<&Path, Status> {
        self.keysfile_path
            .as_deref()
            .ok_or_else(|| Status::failed_precondition("wallet daemon is not synced yet, loading the wallet UTXO set"))
    }

    /// Record outpoints spent by a freshly-broadcast transaction
    /// into the daemon's `used_outpoints` map and poke the sync
    /// loop's force-refresh channel so the UTXO snapshot catches
    /// up without waiting for the next 1-second tick.
    async fn record_spent_outpoints_and_force_sync(&self, spent: Vec<Vec<TransactionOutpoint>>) {
        if let Some(state) = self.state.as_ref() {
            let now = Instant::now();
            let mut guard = state.lock().await;
            for batch in &spent {
                for outpoint in batch {
                    guard.used_outpoints.insert(*outpoint, now);
                }
            }
        }
        if let Some(force_sync) = self.force_sync.as_ref() {
            force_sync.notify_one();
        }
    }

    /// Resolve the request's FeePolicy against the kaspad node's
    /// current feerate estimate, returning `(fee_rate, max_fee)`.
    /// `None` and `MaxFee` policies cap with the
    /// `normal_buckets[0]` recommendation; `ExactFeeRate` uses the
    /// caller's value verbatim (validated against `MIN_FEE_RATE`);
    /// `MaxFeeRate` clamps the kaspad recommendation against the
    /// caller's ceiling.
    async fn calculate_fee_limits(&self, request_fee_policy: Option<FeePolicy>) -> Result<(f64, u64), Status> {
        let kaspad = self.kaspad_or_unsynced()?;
        let policy = request_fee_policy.and_then(|p| p.fee_policy);
        match policy {
            Some(FeePolicyOneof::ExactFeeRate(rate)) => {
                if rate < MIN_FEE_RATE {
                    return Err(Status::invalid_argument(format!(
                        "requested fee rate {rate} is too low, minimum fee rate is {MIN_FEE_RATE}"
                    )));
                }
                Ok((rate, u64::MAX))
            }
            Some(FeePolicyOneof::MaxFeeRate(max_rate)) => {
                if max_rate < MIN_FEE_RATE {
                    return Err(Status::invalid_argument(format!(
                        "requested max fee rate {max_rate} is too low, minimum fee rate is {MIN_FEE_RATE}"
                    )));
                }
                let estimate =
                    kaspad.get_fee_estimate().await.map_err(|e| Status::internal(format!("kaspad get_fee_estimate: {e}")))?;
                let normal = first_normal_bucket(&estimate)?;
                Ok((normal.feerate.min(max_rate), u64::MAX))
            }
            Some(FeePolicyOneof::MaxFee(max_fee)) => {
                let estimate =
                    kaspad.get_fee_estimate().await.map_err(|e| Status::internal(format!("kaspad get_fee_estimate: {e}")))?;
                let normal = first_normal_bucket(&estimate)?;
                Ok((normal.feerate, max_fee))
            }
            None => {
                let estimate =
                    kaspad.get_fee_estimate().await.map_err(|e| Status::internal(format!("kaspad get_fee_estimate: {e}")))?;
                let normal = first_normal_bucket(&estimate)?;
                Ok((normal.feerate, SOMPI_PER_KASPA))
            }
        }
    }

    /// Resolve the change address. When `from_addresses` is
    /// non-empty AND `use_existing` is true, recycle the first
    /// source-address as the change sink; otherwise bump the
    /// keyfile's `last_used_internal_index` (index 0 only when
    /// `use_existing` is true; every other call bumps), persist the
    /// keyfile, and derive the address at the new internal index.
    fn change_address(
        state: &mut DaemonState,
        keysfile_path: &Path,
        use_existing: bool,
        from_addresses: &[WalletAddress],
    ) -> Result<(Address, WalletAddress), Status> {
        let wallet_addr = if !from_addresses.is_empty() && use_existing {
            from_addresses[0]
        } else {
            let cosigner_index = state.keyfile.cosigner_index;
            let internal_index = if use_existing {
                0
            } else {
                let bumped = state.progress.last_used_internal_index.saturating_add(1);
                state.progress.last_used_internal_index = bumped;
                state.keyfile.last_used_internal_index = bumped;
                keyfile::save_to_path(&state.keyfile, keysfile_path)
                    .map_err(|e| Status::internal(format!("keyfile save failed: {e}")))?;
                bumped
            };
            WalletAddress { cosigner_index, key_chain: KeyChain::Internal, index: internal_index }
        };
        let address =
            state.wallet_address(wallet_addr).map_err(|e| Status::internal(format!("change-address derivation failed: {e}")))?;
        Ok((address, wallet_addr))
    }

    /// Resolve operator-supplied `from` address strings against the
    /// daemon's `address_set`. Unknown addresses are an immediate
    /// `Status::invalid_argument`.
    fn resolve_from_addresses(state: &DaemonState, raw: &[String]) -> Result<Vec<WalletAddress>, Status> {
        let mut out = Vec::with_capacity(raw.len());
        for s in raw {
            match state.address_set.get(s) {
                Some(addr) => out.push(*addr),
                None => return Err(Status::invalid_argument(format!("specified from address {s} does not exists"))),
            }
        }
        Ok(out)
    }

    /// Filter the daemon's UTXO snapshot before coin selection:
    ///
    /// 1. drop UTXOs whose wallet-address is not in
    ///    `from_addresses` (no-op when `from_addresses` is empty),
    /// 2. drop UTXOs that fail the coinbase-maturity gate
    ///    (`is_utxo_spendable`),
    /// 3. drop UTXOs whose outpoint sits in `used_outpoints` and
    ///    whose broadcast-time has not yet expired (1-minute
    ///    window) UNLESS the outpoint sits in `allow_used` (the
    ///    BumpFee carve-out). Expired entries are removed from
    ///    `used_outpoints` as a side effect.
    ///
    /// Returns the filtered slice in the same descending-amount
    /// order the daemon's snapshot maintains, converted to the
    /// `LibUtxo` shape the coin-selection layer consumes.
    fn filter_utxos(
        state: &mut DaemonState,
        from_addresses: &[WalletAddress],
        allow_used: &HashSet<TransactionOutpoint>,
        virtual_daa_score: u64,
    ) -> Vec<LibUtxo> {
        let now = Instant::now();
        let mut expired: Vec<TransactionOutpoint> = Vec::new();
        let mut filtered: Vec<LibUtxo> = Vec::new();
        for utxo in &state.utxos_sorted_by_amount {
            if !from_addresses.is_empty() && !from_addresses.contains(&utxo.address) {
                continue;
            }
            if !state.is_utxo_spendable(utxo, virtual_daa_score) {
                continue;
            }
            if let Some(broadcast_time) = state.used_outpoints.get(&utxo.outpoint)
                && !allow_used.contains(&utxo.outpoint)
            {
                if now >= *broadcast_time + super::state::USED_OUTPOINT_EXPIRY {
                    expired.push(utxo.outpoint);
                } else {
                    continue;
                }
            }
            let path = state.wallet_address_path(utxo.address);
            filtered.push(wallet_utxo_to_lib_utxo(utxo, path));
        }
        for outpoint in expired {
            state.used_outpoints.remove(&outpoint);
        }
        filtered
    }

    /// Build an unsigned-PST batch for the requested send. Shared
    /// by `CreateUnsignedTransactions` and `Send`: decode the
    /// recipient, resolve the `from` set, compute fee limits,
    /// allocate a change address, run coin selection, emit the
    /// unsigned PST, and pass through the splitter.
    async fn create_unsigned_transactions_inner(
        &self,
        address: &str,
        amount: u64,
        is_send_all: bool,
        from_raw: &[String],
        use_existing_change_address: bool,
        request_fee_policy: Option<FeePolicy>,
    ) -> Result<Vec<Vec<u8>>, Status> {
        let (fee_rate, max_fee) = self.calculate_fee_limits(request_fee_policy).await?;
        let kaspad = self.kaspad_or_unsynced()?;
        let dag_info = kaspad.get_block_dag_info().await.map_err(|e| Status::internal(format!("kaspad get_block_dag_info: {e}")))?;
        let virtual_daa_score = dag_info.virtual_daa_score;
        let mut state = self.state_or_unsynced().await?;
        let keysfile_path = self.keysfile_path_or_unsynced()?.to_path_buf();

        let to_address =
            Address::try_from(address).map_err(|e| Status::invalid_argument(format!("invalid recipient address '{address}': {e}")))?;
        if to_address.prefix != state.address_prefix {
            return Err(Status::invalid_argument(format!(
                "recipient address prefix '{}' does not match wallet network '{}'",
                to_address.prefix, state.address_prefix
            )));
        }

        let from_addresses = Self::resolve_from_addresses(&state, from_raw)?;
        let (change_address, change_wallet_address) =
            Self::change_address(&mut state, &keysfile_path, use_existing_change_address, &from_addresses)?;
        let change_path = state.wallet_address_path(change_wallet_address);

        let cfg = wallet_config_from_state(&state);
        let params = state.params();
        let filtered = Self::filter_utxos(&mut state, &from_addresses, &HashSet::new(), virtual_daa_score);

        // Drop the lock around the synchronous coin-selection +
        // splitter work so concurrent view RPCs are not blocked
        // for the duration. The daemon-level inputs (filtered UTXO
        // pool, fee limits, change address) are already snapshot.
        drop(state);

        let selection = select_utxos(&cfg, params, &filtered, &[], amount, is_send_all, fee_rate, max_fee)
            .map_err(|e| Status::internal(format!("coin selection failed: {e}")))?;
        unsigned_transactions_from_selection(
            &cfg,
            params,
            selection,
            &to_address,
            &change_address,
            &change_path,
            &filtered,
            amount,
            fee_rate,
            max_fee,
        )
    }

    /// Sign each PSTX in the supplied batch under `password`'s
    /// decrypted mnemonics. Shared by `Sign`, `Send`, `BumpFee`:
    /// decrypt mnemonics once, walk every unsigned PSTX, and
    /// dispatch to Schnorr or ECDSA per the keyfile's `ecdsa` flag.
    fn sign_transactions(keyfile: &KeysFile, unsigned: &[Vec<u8>], password: &str) -> Result<Vec<Vec<u8>>, Status> {
        let mnemonics = keyfile::decrypt_mnemonics(keyfile, password.as_bytes())
            .map_err(|e| Status::invalid_argument(format!("keyfile decryption failed: {e}")))?;
        let mut signed = Vec::with_capacity(unsigned.len());
        for bytes in unsigned {
            let mut pst = serialization::deserialize_partially_signed_transaction(bytes)
                .map_err(|e| Status::invalid_argument(format!("PSTX deserialization failed: {e}")))?;
            for mnemonic in mnemonics.iter() {
                if keyfile.ecdsa {
                    sign_pst_ecdsa_with_mnemonic(&mut pst, mnemonic, "")
                        .map_err(|e| Status::internal(format!("ECDSA sign failed: {e}")))?;
                } else {
                    sign_pst_schnorr_with_mnemonic(&mut pst, mnemonic, "")
                        .map_err(|e| Status::internal(format!("Schnorr sign failed: {e}")))?;
                }
            }
            let bytes = serialization::serialize_partially_signed_transaction(&pst)
                .map_err(|e| Status::internal(format!("PSTX serialization failed: {e}")))?;
            signed.push(bytes);
        }
        Ok(signed)
    }

    /// Submit each transaction in the batch via plain
    /// `SubmitTransaction`, returning the list of accepted tx-ids
    /// in submission order. Shared by `Broadcast` and `Send`.
    async fn broadcast_inner(&self, transactions: &[Vec<u8>], is_domain: bool) -> Result<Vec<String>, Status> {
        let kaspad = self.kaspad_or_unsynced()?;
        let ecdsa = self.state_or_unsynced().await?.keyfile.ecdsa;

        let mut tx_ids = Vec::with_capacity(transactions.len());
        let mut spent: Vec<Vec<TransactionOutpoint>> = Vec::with_capacity(transactions.len());
        for bytes in transactions {
            let tx = decode_broadcast_tx(bytes, is_domain, ecdsa)?;
            let inputs: Vec<TransactionOutpoint> = tx.inputs.iter().map(|i| i.previous_outpoint).collect();
            let txid = kaspad
                .submit_transaction(RpcTransaction::from(&tx), false)
                .await
                .map_err(|e| Status::internal(format!("kaspad submit_transaction: {e}")))?;
            tx_ids.push(txid.to_string());
            spent.push(inputs);
        }
        self.record_spent_outpoints_and_force_sync(spent).await;
        Ok(tx_ids)
    }

    /// Submit each transaction via `SubmitTransactionReplacement`
    /// for the first entry and plain `SubmitTransaction` for the
    /// rest. Shared by `BroadcastReplacement` and `BumpFee`: only
    /// the first tx goes through RBF; chained txs assume the
    /// replacement landed and use the standard submit path.
    async fn broadcast_replacement_inner(&self, transactions: &[Vec<u8>], is_domain: bool) -> Result<Vec<String>, Status> {
        let kaspad = self.kaspad_or_unsynced()?;
        let ecdsa = self.state_or_unsynced().await?.keyfile.ecdsa;

        let mut tx_ids = Vec::with_capacity(transactions.len());
        let mut spent: Vec<Vec<TransactionOutpoint>> = Vec::with_capacity(transactions.len());
        for (i, bytes) in transactions.iter().enumerate() {
            let tx = decode_broadcast_tx(bytes, is_domain, ecdsa)?;
            let inputs: Vec<TransactionOutpoint> = tx.inputs.iter().map(|inp| inp.previous_outpoint).collect();
            let txid = if i == 0 {
                let resp = kaspad
                    .submit_transaction_replacement(RpcTransaction::from(&tx))
                    .await
                    .map_err(|e| Status::internal(format!("kaspad submit_transaction_replacement: {e}")))?;
                resp.transaction_id
            } else {
                kaspad
                    .submit_transaction(RpcTransaction::from(&tx), false)
                    .await
                    .map_err(|e| Status::internal(format!("kaspad submit_transaction: {e}")))?
            };
            tx_ids.push(txid.to_string());
            spent.push(inputs);
        }
        self.record_spent_outpoints_and_force_sync(spent).await;
        Ok(tx_ids)
    }
}

#[tonic::async_trait]
impl Kaspawalletd for KaspawalletdSvc {
    async fn get_balance(&self, _request: Request<GetBalanceRequest>) -> Result<Response<GetBalanceResponse>, Status> {
        // Walk `utxos_sorted_by_amount` and split each UTXO into
        // `available` (matured, spendable) or `pending` (immature
        // coinbase awaiting the COINBASE_MATURITY DAA gate) via
        // `is_utxo_spendable(entry, virtual_daa_score)`. The
        // `mempool_excluded_utxos` set is intentionally NOT counted
        // into either bucket -- mempool-conflicted outpoints are
        // tracked separately for the BumpFee carve-out and do not
        // appear in the user-visible balance.
        let kaspad = self.kaspad_or_unsynced()?;
        let dag_info = kaspad.get_block_dag_info().await.map_err(|e| Status::internal(format!("kaspad get_block_dag_info: {e}")))?;
        let virtual_daa_score = dag_info.virtual_daa_score;

        let state = self.state_or_unsynced().await?;
        let mut available_total: u64 = 0;
        let mut pending_total: u64 = 0;
        let mut by_address: std::collections::BTreeMap<String, (u64, u64)> = std::collections::BTreeMap::new();
        for utxo in &state.utxos_sorted_by_amount {
            let entry = by_address.entry(utxo.address_string.clone()).or_insert((0, 0));
            if state.is_utxo_spendable(utxo, virtual_daa_score) {
                entry.0 = entry.0.saturating_add(utxo.utxo_entry.amount);
                available_total = available_total.saturating_add(utxo.utxo_entry.amount);
            } else {
                entry.1 = entry.1.saturating_add(utxo.utxo_entry.amount);
                pending_total = pending_total.saturating_add(utxo.utxo_entry.amount);
            }
        }
        let address_balances =
            by_address.into_iter().map(|(address, (available, pending))| AddressBalances { address, available, pending }).collect();
        Ok(Response::new(GetBalanceResponse { available: available_total, pending: pending_total, address_balances }))
    }

    async fn get_external_spendable_utx_os(
        &self,
        request: Request<GetExternalSpendableUtxOsRequest>,
    ) -> Result<Response<GetExternalSpendableUtxOsResponse>, Status> {
        let target_address = request.into_inner().address;
        let state = self.state_or_unsynced().await?;
        let entries: Vec<UtxosByAddressesEntry> = state
            .utxos_sorted_by_amount
            .iter()
            .filter(|utxo| utxo.address.key_chain == KeyChain::External && utxo.address_string == target_address)
            .map(utxo_to_pb)
            .collect();
        Ok(Response::new(GetExternalSpendableUtxOsResponse { entries }))
    }

    async fn create_unsigned_transactions(
        &self,
        request: Request<CreateUnsignedTransactionsRequest>,
    ) -> Result<Response<CreateUnsignedTransactionsResponse>, Status> {
        let req = request.into_inner();
        let unsigned = self
            .create_unsigned_transactions_inner(
                &req.address,
                req.amount,
                req.is_send_all,
                &req.from,
                req.use_existing_change_address,
                req.fee_policy,
            )
            .await?;
        Ok(Response::new(CreateUnsignedTransactionsResponse { unsigned_transactions: unsigned }))
    }

    async fn show_addresses(&self, _request: Request<ShowAddressesRequest>) -> Result<Response<ShowAddressesResponse>, Status> {
        let state = self.state_or_unsynced().await?;
        let cosigner_index = state.keyfile.cosigner_index;
        let last_used = state.progress.last_used_external_index;
        let mut addresses = Vec::with_capacity(last_used as usize);
        for index in 1..=last_used {
            let wallet_addr = WalletAddress { cosigner_index, key_chain: KeyChain::External, index };
            let address_string = state
                .wallet_address_string(wallet_addr)
                .map_err(|e| Status::internal(format!("address derivation failed at index {index}: {e}")))?;
            addresses.push(address_string);
        }
        Ok(Response::new(ShowAddressesResponse { address: addresses }))
    }

    async fn new_address(&self, _request: Request<NewAddressRequest>) -> Result<Response<NewAddressResponse>, Status> {
        let keysfile_path = self.keysfile_path_or_unsynced()?.to_path_buf();
        let mut state = self.state_or_unsynced().await?;

        // Bump `last_used_external_index`, persist the keyfile,
        // derive the address at the new index.
        let new_index = state.progress.last_used_external_index.saturating_add(1);
        state.progress.last_used_external_index = new_index;
        state.keyfile.last_used_external_index = new_index;
        keyfile::save_to_path(&state.keyfile, &keysfile_path).map_err(|e| Status::internal(format!("keyfile save failed: {e}")))?;

        let cosigner_index = state.keyfile.cosigner_index;
        let wallet_addr = WalletAddress { cosigner_index, key_chain: KeyChain::External, index: new_index };
        let address_string = state
            .wallet_address_string(wallet_addr)
            .map_err(|e| Status::internal(format!("address derivation failed at index {new_index}: {e}")))?;
        // Register the new address in the daemon's address-set so
        // the next UTXO refresh covers it.
        state.address_set.insert(address_string.clone(), wallet_addr);
        Ok(Response::new(NewAddressResponse { address: address_string }))
    }

    async fn shutdown(&self, _request: Request<ShutdownRequest>) -> Result<Response<ShutdownResponse>, Status> {
        // `notify_one` stores a permit when no waiter is currently
        // registered, so a `Shutdown` RPC that races ahead of the
        // server-side `combined_shutdown` future still terminates
        // the daemon when that future first polls. `notify_waiters`
        // would silently drop the signal in the same race.
        self.shutdown.notify_one();
        Ok(Response::new(ShutdownResponse {}))
    }

    async fn broadcast(&self, request: Request<BroadcastRequest>) -> Result<Response<BroadcastResponse>, Status> {
        let req = request.into_inner();
        let tx_ids = self.broadcast_inner(&req.transactions, req.is_domain).await?;
        Ok(Response::new(BroadcastResponse { tx_i_ds: tx_ids }))
    }

    async fn broadcast_replacement(&self, request: Request<BroadcastRequest>) -> Result<Response<BroadcastResponse>, Status> {
        let req = request.into_inner();
        let tx_ids = self.broadcast_replacement_inner(&req.transactions, req.is_domain).await?;
        Ok(Response::new(BroadcastResponse { tx_i_ds: tx_ids }))
    }

    async fn send(&self, request: Request<SendRequest>) -> Result<Response<SendResponse>, Status> {
        let mut req = request.into_inner();
        let unsigned = self
            .create_unsigned_transactions_inner(
                &req.to_address,
                req.amount,
                req.is_send_all,
                &req.from,
                req.use_existing_change_address,
                req.fee_policy,
            )
            .await?;

        let keyfile = self.state_or_unsynced().await?.keyfile.clone();
        let password = Zeroizing::new(std::mem::take(&mut req.password));
        let signed = Self::sign_transactions(&keyfile, &unsigned, &password)?;
        // Send always submits via the standard mempool path
        // (no RBF on the first-pass `send` flow).
        let tx_ids = self.broadcast_inner(&signed, false).await?;
        Ok(Response::new(SendResponse { tx_i_ds: tx_ids, signed_transactions: signed }))
    }

    async fn sign(&self, request: Request<SignRequest>) -> Result<Response<SignResponse>, Status> {
        let mut req = request.into_inner();
        let keyfile = self.state_or_unsynced().await?.keyfile.clone();
        let password = Zeroizing::new(std::mem::take(&mut req.password));
        let signed = Self::sign_transactions(&keyfile, &req.unsigned_transactions, &password)?;
        Ok(Response::new(SignResponse { signed_transactions: signed }))
    }

    async fn get_version(&self, _request: Request<GetVersionRequest>) -> Result<Response<GetVersionResponse>, Status> {
        Ok(Response::new(GetVersionResponse { version: self.version.clone() }))
    }

    async fn bump_fee(&self, request: Request<BumpFeeRequest>) -> Result<Response<BumpFeeResponse>, Status> {
        let mut req = request.into_inner();
        let kaspad = self.kaspad_or_unsynced()?.clone();

        let tx_id = RpcTransactionId::from_str(&req.tx_id)
            .map_err(|e| Status::invalid_argument(format!("invalid tx_id '{}': {e}", req.tx_id)))?;
        let entry = kaspad
            .get_mempool_entry(tx_id, false, false)
            .await
            .map_err(|e| Status::internal(format!("kaspad get_mempool_entry: {e}")))?;
        let domain_tx: Transaction = entry
            .transaction
            .try_into()
            .map_err(|e| Status::internal(format!("kaspad RpcTransaction -> Transaction conversion failed: {e}")))?;
        let original_fee = entry.fee;

        let dag_info = kaspad.get_block_dag_info().await.map_err(|e| Status::internal(format!("kaspad get_block_dag_info: {e}")))?;
        let virtual_daa_score = dag_info.virtual_daa_score;
        let mut state = self.state_or_unsynced().await?;
        let keysfile_path = self.keysfile_path_or_unsynced()?.to_path_buf();

        // Walk the original transaction's inputs, find them in
        // `mempool_excluded_utxos` (or fall back to
        // `utxos_sorted_by_amount`), and pick the highest-amount
        // entry as the seed UTXO. The `allow_used` set is the
        // BumpFee carve-out the coin-selector observes.
        let mut allow_used: HashSet<TransactionOutpoint> = HashSet::with_capacity(domain_tx.inputs.len());
        for input in &domain_tx.inputs {
            allow_used.insert(input.previous_outpoint);
        }
        let mut max_seed: Option<crate::daemon::state::WalletUtxo> = None;
        for outpoint in &allow_used {
            if let Some(utxo) = state.mempool_excluded_utxos.get(outpoint).cloned() {
                match max_seed.as_ref() {
                    None => max_seed = Some(utxo),
                    Some(current) if utxo.utxo_entry.amount > current.utxo_entry.amount => max_seed = Some(utxo),
                    _ => {}
                }
            }
        }
        if max_seed.is_none() {
            // Fallback: scan utxos_sorted_by_amount for any of the
            // original inputs. The two iterations target disjoint
            // snapshots of the daemon state, so order is preserved.
            for utxo in &state.utxos_sorted_by_amount {
                if !allow_used.contains(&utxo.outpoint) {
                    continue;
                }
                match max_seed.as_ref() {
                    None => max_seed = Some(utxo.clone()),
                    Some(current) if utxo.utxo_entry.amount > current.utxo_entry.amount => max_seed = Some(utxo.clone()),
                    _ => {}
                }
            }
        }
        let max_utxo = max_seed.ok_or_else(|| {
            Status::failed_precondition(format!(
                "no UTXOs were found for transaction {}. This probably means the transaction is already accepted",
                req.tx_id
            ))
        })?;

        // Compute the original fee rate via consensus mass.
        // `overall_mass = max(compute_mass, storage_mass)`: the
        // signed mempool transaction's compute mass comes from the
        // non-contextual calculator; the storage mass needs each
        // input's previous-output amount, recovered from the
        // daemon's `mempool_excluded_utxos`.
        let original_fee_rate =
            calc_overall_mass_fee_rate(&state, &domain_tx, original_fee).map_err(|e| Status::internal(format!("mass calc: {e}")))?;

        let (new_fee_rate, max_fee) = self.calculate_fee_limits(req.fee_policy).await?;
        if new_fee_rate <= original_fee_rate {
            return Err(Status::invalid_argument(format!(
                "new fee rate ({new_fee_rate:.6}) is not higher than the current fee rate ({original_fee_rate:.6})"
            )));
        }
        if domain_tx.outputs.is_empty() || domain_tx.outputs.len() > 2 {
            return Err(Status::invalid_argument(format!(
                "kaspawallet supports only transactions with 1 or 2 outputs in transaction {}, but this transaction got {}",
                req.tx_id,
                domain_tx.outputs.len()
            )));
        }

        let from_addresses = Self::resolve_from_addresses(&state, &req.from)?;
        let (change_address, change_wallet_address) =
            Self::change_address(&mut state, &keysfile_path, req.use_existing_change_address, &from_addresses)?;
        let change_path = state.wallet_address_path(change_wallet_address);

        let cfg = wallet_config_from_state(&state);
        let params = state.params();
        let pre_path = state.wallet_address_path(max_utxo.address);
        let pre_selected = vec![wallet_utxo_to_lib_utxo(&max_utxo, pre_path)];
        let filtered = Self::filter_utxos(&mut state, &from_addresses, &allow_used, virtual_daa_score);
        let to_address = extract_script_pub_key_address(&domain_tx.outputs[0].script_public_key, state.address_prefix)
            .map_err(|e| Status::internal(format!("recipient script extraction failed: {e}")))?;
        let recipient_value = domain_tx.outputs[0].value;

        drop(state);

        let selection = select_utxos(&cfg, params, &filtered, &pre_selected, recipient_value, false, new_fee_rate, max_fee)
            .map_err(|e| Status::internal(format!("coin selection failed: {e}")))?;
        if selection.selected.is_empty() {
            return Err(Status::failed_precondition("couldn't find funds to spend"));
        }
        let unsigned = unsigned_transactions_from_selection(
            &cfg,
            params,
            selection,
            &to_address,
            &change_address,
            &change_path,
            &filtered,
            recipient_value,
            new_fee_rate,
            max_fee,
        )?;

        if req.password.is_empty() {
            return Ok(Response::new(BumpFeeResponse { transactions: unsigned, tx_i_ds: Vec::new() }));
        }

        let keyfile = self.state_or_unsynced().await?.keyfile.clone();
        let password = Zeroizing::new(std::mem::take(&mut req.password));
        let signed = Self::sign_transactions(&keyfile, &unsigned, &password)?;
        let tx_ids = self.broadcast_replacement_inner(&signed, false).await?;
        Ok(Response::new(BumpFeeResponse { transactions: signed, tx_i_ds: tx_ids }))
    }
}

fn utxo_to_pb(utxo: &super::state::WalletUtxo) -> UtxosByAddressesEntry {
    let script_public_key = ScriptPublicKey {
        version: utxo.utxo_entry.script_public_key.version() as u32,
        script_public_key: hex::encode(utxo.utxo_entry.script_public_key.script()),
    };
    UtxosByAddressesEntry {
        address: utxo.address_string.clone(),
        outpoint: Some(Outpoint { transaction_id: utxo.outpoint.transaction_id.to_string(), index: utxo.outpoint.index }),
        utxo_entry: Some(UtxoEntry {
            amount: utxo.utxo_entry.amount,
            script_public_key: Some(script_public_key),
            block_daa_score: utxo.utxo_entry.block_daa_score,
            is_coinbase: utxo.utxo_entry.is_coinbase,
        }),
    }
}

/// Decode the broadcast-RPC's transaction payload. The
/// `is_domain=true` branch consumes a raw consensus-tx wire blob;
/// the `is_domain=false` branch consumes a signed PSTX and
/// extracts the consensus-tx via the sign module's
/// `extract_transaction`.
fn decode_broadcast_tx(bytes: &[u8], is_domain: bool, ecdsa: bool) -> Result<Transaction, Status> {
    if is_domain {
        let msg = serialization::deserialize_domain_transaction(bytes)
            .map_err(|e| Status::invalid_argument(format!("domain-tx deserialization failed: {e}")))?;
        crate::sign::wire::wire_to_consensus_tx(&msg)
            .map_err(|e| Status::invalid_argument(format!("domain-tx wire->consensus conversion failed: {e}")))
    } else {
        let pst = serialization::deserialize_partially_signed_transaction(bytes)
            .map_err(|e| Status::invalid_argument(format!("PSTX deserialization failed: {e}")))?;
        extract_transaction(&pst, ecdsa).map_err(|e| Status::invalid_argument(format!("PSTX extraction failed: {e}")))
    }
}

/// Build a `WalletConfig` snapshot from the daemon state. The
/// snapshot is the input the coin-selection layer needs in order
/// to construct fee-estimation mock transactions; all fields come
/// from the keyfile + the active network's address prefix.
fn wallet_config_from_state(state: &DaemonState) -> WalletConfig {
    WalletConfig {
        extended_public_keys: state.keyfile.extended_public_keys.clone(),
        minimum_signatures: state.keyfile.minimum_signatures,
        address_prefix: state.address_prefix,
        ecdsa: state.keyfile.ecdsa,
    }
}

/// Lift a `WalletUtxo` into the `LibUtxo` shape the
/// coin-selection layer consumes. The outpoint hash is encoded
/// into the proto `Outpoint`'s 32-byte `TransactionId.bytes`
/// field, exactly as the daemon's existing test-side helpers do.
fn wallet_utxo_to_lib_utxo(utxo: &super::state::WalletUtxo, derivation_path: String) -> LibUtxo {
    LibUtxo {
        outpoint: serialization::wire::Outpoint {
            transaction_id: Some(serialization::wire::TransactionId { bytes: utxo.outpoint.transaction_id.as_bytes().to_vec() }),
            index: utxo.outpoint.index,
        },
        utxo_entry: kaspa_consensus_core::tx::UtxoEntry {
            amount: utxo.utxo_entry.amount,
            script_public_key: utxo.utxo_entry.script_public_key.clone(),
            block_daa_score: utxo.utxo_entry.block_daa_score,
            is_coinbase: utxo.utxo_entry.is_coinbase,
        },
        derivation_path,
    }
}

/// Emit the unsigned-PSTX batch from a coin-selection
/// `Selection`: build the `payments` (recipient + optional
/// change), call `create_unsigned_transaction`, then run the
/// splitter via `maybe_auto_compound_transaction`. The splitter
/// receives the post-filter "spare" UTXO pool minus anything the
/// selection already consumed -- the merge step needs that pool
/// when the splits do not cover the original recipient amount.
#[allow(clippy::too_many_arguments)] // collapsing into a struct hurts call-site clarity
fn unsigned_transactions_from_selection(
    cfg: &WalletConfig,
    params: &kaspa_consensus_core::config::params::Params,
    selection: Selection,
    to_address: &Address,
    change_address: &Address,
    change_derivation_path: &str,
    filtered_pool: &[LibUtxo],
    spend_amount: u64,
    fee_rate: f64,
    max_fee: u64,
) -> Result<Vec<Vec<u8>>, Status> {
    if selection.selected.is_empty() {
        return Err(Status::failed_precondition("couldn't find funds to spend"));
    }

    let mut payments: Vec<Payment> = vec![Payment { address: to_address.clone(), amount: selection.total_received }];
    if selection.change_sompi > 0 {
        payments.push(Payment { address: change_address.clone(), amount: selection.change_sompi });
    }
    let _ = spend_amount; // amount lives inside `selection.total_received`

    let unsigned_pst = create_unsigned_transaction(&cfg.extended_public_keys, cfg.minimum_signatures, &payments, &selection.selected)
        .map_err(|e| Status::internal(format!("create_unsigned_transaction failed: {e}")))?;

    let selected_keys: HashSet<(Vec<u8>, u32)> = selection
        .selected
        .iter()
        .map(|u| (u.outpoint.transaction_id.as_ref().map(|t| t.bytes.clone()).unwrap_or_default(), u.outpoint.index))
        .collect();
    let spare_pool: Vec<LibUtxo> = filtered_pool
        .iter()
        .filter(|u| {
            let key = (u.outpoint.transaction_id.as_ref().map(|t| t.bytes.clone()).unwrap_or_default(), u.outpoint.index);
            !selected_keys.contains(&key)
        })
        .cloned()
        .collect();

    maybe_auto_compound_transaction(
        cfg,
        params,
        unsigned_pst,
        to_address,
        change_address,
        change_derivation_path,
        fee_rate,
        max_fee,
        &spare_pool,
    )
    .map_err(|e| Status::internal(format!("transaction splitter failed: {e}")))
}

/// Pick the first normal-priority feerate bucket from a kaspad
/// fee estimate. Returns an `internal` status when kaspad's
/// response carries an empty normal-bucket vector (the protocol
/// guarantees at least one entry; an empty response is a
/// node-side bug).
fn first_normal_bucket(estimate: &kaspa_rpc_core::RpcFeeEstimate) -> Result<kaspa_rpc_core::RpcFeerateBucket, Status> {
    estimate.normal_buckets.first().copied().ok_or_else(|| Status::internal("kaspad fee estimate is missing normal buckets"))
}

/// Compute `fee / overall_mass` for a signed transaction.
/// `overall_mass = max(compute_mass, storage_mass)`. The compute
/// component comes from the consensus-core non-contextual mass
/// calculator; the storage component is the KIP-0009 formula
/// evaluated against each input's previous-output amount, which
/// the daemon recovers from `mempool_excluded_utxos`. Inputs whose
/// previous-output is not in `mempool_excluded_utxos` AND not in
/// `utxos_sorted_by_amount` produce an error -- the storage mass
/// formula has no defined value without all input amounts.
fn calc_overall_mass_fee_rate(state: &DaemonState, tx: &Transaction, fee: u64) -> Result<f64, String> {
    let params = state.params();
    let mass_calc = kaspa_consensus_core::mass::MassCalculator::new(
        params.mass_per_tx_byte,
        params.mass_per_script_pub_key_byte,
        params.mass_per_sig_op,
        params.storage_mass_parameter,
    );
    let compute_mass = mass_calc.calc_non_contextual_masses(tx).compute_mass;

    let mut input_cells: Vec<kaspa_consensus_core::mass::UtxoCell> = Vec::with_capacity(tx.inputs.len());
    for input in &tx.inputs {
        let outpoint = input.previous_outpoint;
        let amount = state
            .mempool_excluded_utxos
            .get(&outpoint)
            .map(|u| u.utxo_entry.amount)
            .or_else(|| state.utxos_sorted_by_amount.iter().find(|u| u.outpoint == outpoint).map(|u| u.utxo_entry.amount))
            .ok_or_else(|| format!("input {outpoint:?} not found in daemon UTXO snapshot"))?;
        if amount == 0 {
            return Err(format!("input {outpoint:?} has zero amount"));
        }
        input_cells.push(kaspa_consensus_core::mass::UtxoCell::new(1, amount));
    }
    let output_cells: Vec<kaspa_consensus_core::mass::UtxoCell> =
        tx.outputs.iter().map(|o| kaspa_consensus_core::mass::UtxoCell::new(1, o.value)).collect();
    let storage_mass = kaspa_consensus_core::mass::calc_storage_mass(
        false,
        input_cells.into_iter(),
        output_cells.into_iter(),
        params.storage_mass_parameter,
    )
    .unwrap_or(0);

    let overall = compute_mass.max(storage_mass);
    if overall == 0 {
        return Err("overall mass evaluated to zero".to_owned());
    }
    Ok(fee as f64 / overall as f64)
}
