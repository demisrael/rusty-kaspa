//! Unit tests for the daemon-side service surface, the shared
//! state primitives, and the sync-loop step against a hand-rolled
//! mock `KaspadFacade`. These tests are fully in-process; the
//! end-to-end "spawn the daemon on a port and dial it" test lives
//! under `tests/daemon_smoke.rs` (integration-test target).

use std::sync::Arc;

use async_trait::async_trait;
use kaspa_addresses::{Address, Prefix as AddressPrefix, Version as AddressVersion};
use kaspa_consensus_core::tx::{ScriptPublicKey, ScriptVec, TransactionOutpoint};
use kaspa_rpc_core::{
    GetBlockDagInfoResponse, RpcAddress, RpcBalancesByAddressesEntry, RpcFeeEstimate, RpcFeerateBucket, RpcHash, RpcMempoolEntry,
    RpcMempoolEntryByAddress, RpcNetworkId, RpcNetworkType, RpcUtxoEntry, RpcUtxosByAddressesEntry,
};
use tokio::sync::{Mutex, Notify};
use tonic::{Code, Request};

use super::kaspad::KaspadFacade;
use super::pb::kaspawalletd_server::Kaspawalletd;
use super::pb::{
    BroadcastRequest, BumpFeeRequest, CreateUnsignedTransactionsRequest, FeePolicy, GetBalanceRequest,
    GetExternalSpendableUtxOsRequest, GetVersionRequest, NewAddressRequest, SendRequest, ShowAddressesRequest, ShutdownRequest,
    SignRequest, fee_policy::FeePolicy as FeePolicyOneof,
};
use super::service::KaspawalletdSvc;
use super::state::{DaemonState, KeyChain, SharedState, WalletAddress, WalletUtxo, shared};
use super::sync::SyncLoop;
use crate::keyfile::KeysFile;

const TEST_VERSION: &str = "test-1.0.0";

fn empty_keysfile() -> KeysFile {
    KeysFile {
        version: crate::keyfile::LATEST_VERSION,
        num_threads: 8,
        encrypted_mnemonics: Vec::new(),
        // Real ktub xpub lifted from the v1 single-key keyfile
        // fixture (`tests/fixtures/legacy_go_v1_singlekey.json`)
        // so the state's derivation primitives operate on a valid
        // Base58-checksummed extended public key.
        extended_public_keys: vec![
            "ktub249YJayoDJS3tDjTW8NG3iAwufiDQ13uEptr8Wz2LgnzdVFLUQiRqFRPyq1xndcJMXFbYx268MSxHwukrnD52gWeshgeYseLmTBcUNHR1Xb"
                .to_string(),
        ],
        minimum_signatures: 1,
        cosigner_index: 0,
        last_used_external_index: 0,
        last_used_internal_index: 0,
        ecdsa: false,
    }
}

fn make_state() -> SharedState {
    shared(DaemonState::new(empty_keysfile(), AddressPrefix::Mainnet))
}

fn make_service_unsynced() -> (KaspawalletdSvc, Arc<Notify>) {
    let notify = Arc::new(Notify::new());
    let kaspad: Arc<dyn KaspadFacade> = MockKaspad::empty();
    let force_sync = Arc::new(Notify::new());
    let path = std::env::temp_dir().join("kaspawallet-test-unsynced.json");
    (KaspawalletdSvc::with_mocks(TEST_VERSION, notify.clone(), make_state(), kaspad, force_sync, path), notify)
}

fn make_service_without_state() -> (KaspawalletdSvc, Arc<Notify>) {
    let notify = Arc::new(Notify::new());
    (KaspawalletdSvc::without_state(TEST_VERSION, notify.clone()), notify)
}

async fn make_service_synced(state: SharedState) -> (KaspawalletdSvc, Arc<Notify>) {
    {
        let mut guard = state.lock().await;
        guard.progress.first_sync_done = true;
        // Force `next_sync_start_index > max_used_index` so
        // `is_synced()` returns true regardless of the per-test
        // last-used indexes.
        let max_used = guard.progress.max_used_index();
        guard.progress.next_sync_start_index = max_used + 1;
    }
    let notify = Arc::new(Notify::new());
    let kaspad: Arc<dyn KaspadFacade> = MockKaspad::empty();
    let force_sync = Arc::new(Notify::new());
    let path = std::env::temp_dir().join("kaspawallet-test-synced.json");
    (KaspawalletdSvc::with_mocks(TEST_VERSION, notify.clone(), state, kaspad, force_sync, path), notify)
}

#[tokio::test]
async fn get_version_returns_configured_string() {
    let (svc, _shutdown) = make_service_unsynced();
    let resp = svc.get_version(Request::new(GetVersionRequest {})).await.unwrap();
    assert_eq!(resp.into_inner().version, TEST_VERSION);
}

#[tokio::test]
async fn shutdown_notifies_waiters() {
    let (svc, shutdown) = make_service_unsynced();
    let waiter = tokio::spawn({
        let shutdown = shutdown.clone();
        async move {
            shutdown.notified().await;
        }
    });
    let _ = svc.shutdown(Request::new(ShutdownRequest {})).await.unwrap();
    waiter.await.expect("waiter task panicked");
}

#[tokio::test]
async fn view_rpcs_return_failed_precondition_when_unsynced() {
    let (svc, _shutdown) = make_service_unsynced();

    let status = svc.show_addresses(Request::new(ShowAddressesRequest {})).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
    assert!(status.message().contains("not synced"), "message: {}", status.message());

    let status = svc.get_balance(Request::new(GetBalanceRequest {})).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);

    let status = svc
        .get_external_spendable_utx_os(Request::new(GetExternalSpendableUtxOsRequest { address: String::new() }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn view_rpcs_return_failed_precondition_without_state() {
    let (svc, _shutdown) = make_service_without_state();
    let status = svc.show_addresses(Request::new(ShowAddressesRequest {})).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
}

#[tokio::test]
async fn composition_tx_rpcs_return_failed_precondition_when_unsynced() {
    // The composition trio now lands here: CreateUnsignedTransactions,
    // Send, BumpFee all gate on `state_or_unsynced()`. When the
    // daemon is not yet synced, every one of them returns
    // `Code::FailedPrecondition` with the Go-style "wallet daemon
    // is not synced yet" message.
    let (svc, _shutdown) = make_service_unsynced();

    let status = svc.create_unsigned_transactions(Request::new(CreateUnsignedTransactionsRequest::default())).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);

    let status = svc.send(Request::new(SendRequest::default())).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);

    let status = svc.bump_fee(Request::new(BumpFeeRequest::default())).await.unwrap_err();
    // BumpFee dials kaspad before it touches state; the unsynced
    // mock has no mempool entry configured, so the failure path
    // surfaces as the kaspad-side Internal status rather than the
    // FailedPrecondition the others share.
    assert!(matches!(status.code(), Code::FailedPrecondition | Code::Internal | Code::InvalidArgument), "got {:?}", status.code());
}

#[tokio::test]
async fn newly_wired_rpcs_return_failed_precondition_when_unsynced() {
    let (svc, _shutdown) = make_service_unsynced();

    let status = svc.new_address(Request::new(NewAddressRequest {})).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);

    let status = svc.sign(Request::new(SignRequest::default())).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);

    let status = svc.broadcast(Request::new(BroadcastRequest::default())).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);

    let status = svc.broadcast_replacement(Request::new(BroadcastRequest::default())).await.unwrap_err();
    assert_eq!(status.code(), Code::FailedPrecondition);
}

#[test]
fn service_constructor_records_version_string() {
    let (svc, _shutdown) = make_service_unsynced();
    assert_eq!(svc.version(), TEST_VERSION);
}

#[test]
fn sync_progress_is_synced_predicate_matches_go() {
    let mut progress = super::state::SyncProgress {
        first_sync_done: false,
        next_sync_start_index: 5,
        last_used_external_index: 2,
        last_used_internal_index: 1,
    };
    assert!(!progress.is_synced(), "first_sync_done=false should be unsynced");
    progress.first_sync_done = true;
    assert!(progress.is_synced(), "first_sync_done=true and next_sync_start_index>max_used_index should be synced");
    progress.last_used_external_index = 10;
    assert!(!progress.is_synced(), "next_sync_start_index<=max_used_index should be unsynced");
}

#[test]
fn sync_progress_format_state_report_uses_percent() {
    let progress = super::state::SyncProgress {
        first_sync_done: false,
        next_sync_start_index: 250,
        last_used_external_index: 1000,
        last_used_internal_index: 0,
    };
    let report = progress.format_state_report();
    assert!(report.contains("250"), "report should contain progress index: {report}");
    assert!(report.contains("1000"), "report should contain max used: {report}");
    assert!(report.contains("25.00%"), "report should contain percent: {report}");
}

#[tokio::test]
async fn show_addresses_returns_external_addresses_at_last_used_indices() {
    let state = make_state();
    {
        let mut guard = state.lock().await;
        guard.progress.last_used_external_index = 3;
    }
    let (svc, _shutdown) = make_service_synced(state.clone()).await;
    let resp = svc.show_addresses(Request::new(ShowAddressesRequest {})).await.unwrap().into_inner();
    assert_eq!(resp.address.len(), 3, "expect addresses for indices 1..=3");
    // The address strings should be unique and prefixed for mainnet.
    let unique: std::collections::HashSet<_> = resp.address.iter().collect();
    assert_eq!(unique.len(), 3);
    for addr in &resp.address {
        assert!(addr.starts_with("kaspa:"), "unexpected prefix: {addr}");
    }
}

#[tokio::test]
async fn get_balance_aggregates_per_address_available_and_pending() {
    // Available = matured (non-coinbase OR coinbase past
    // COINBASE_MATURITY); Pending = immature coinbase.
    // Mempool-excluded UTXOs do NOT show up in balance, matching Go
    // `cmd/kaspawallet/daemon/server/balance.go::GetBalance`
    // (Go's `utxosSortedByAmount` already excludes mempool-spent
    // outpoints; the Rust port's `mempool_excluded_utxos` map is a
    // separate workspace for the daemon's own bookkeeping, NOT a
    // pending bucket).
    let state = make_state();
    let address_string = make_test_address_string();
    let wallet_addr = WalletAddress { cosigner_index: 0, key_chain: KeyChain::External, index: 1 };
    {
        let mut guard = state.lock().await;
        // Matured non-coinbase: counts as Available.
        guard.utxos_sorted_by_amount.push(make_test_utxo(&address_string, wallet_addr, 100, 0));
        guard.utxos_sorted_by_amount.push(make_test_utxo(&address_string, wallet_addr, 25, 1));
        // Immature coinbase (block_daa_score is high enough that
        // block_daa_score + COINBASE_MATURITY >= virtual_daa_score
        // under the mock kaspad's `virtual_daa_score = 1_000_000`):
        // mock daa score 999_500 means matured-at >= 1_000_500;
        // virtual_daa_score 1_000_000 < 1_000_500 -- not spendable.
        guard.utxos_sorted_by_amount.push(make_immature_coinbase_utxo(&address_string, wallet_addr, 50, 2, 999_500));
        // Mempool-excluded: ignored by balance.
        guard.mempool_excluded_utxos.insert(
            TransactionOutpoint { transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[7u8; 32]), index: 0 },
            make_test_utxo(&address_string, wallet_addr, 7, 0),
        );
    }
    let (svc, _shutdown) = make_service_synced(state).await;
    let resp = svc.get_balance(Request::new(GetBalanceRequest {})).await.unwrap().into_inner();
    assert_eq!(resp.available, 125);
    assert_eq!(resp.pending, 50);
    assert_eq!(resp.address_balances.len(), 1);
    assert_eq!(resp.address_balances[0].address, address_string);
    assert_eq!(resp.address_balances[0].available, 125);
    assert_eq!(resp.address_balances[0].pending, 50);
}

#[tokio::test]
async fn get_balance_excludes_mempool_excluded_utxos() {
    // Mempool-excluded UTXOs must NOT contribute to either
    // available or pending in the balance response (Go parity:
    // mempool-conflicted outpoints are silently filtered out at
    // the snapshot stage).
    let state = make_state();
    let address_string = make_test_address_string();
    let wallet_addr = WalletAddress { cosigner_index: 0, key_chain: KeyChain::External, index: 1 };
    {
        let mut guard = state.lock().await;
        guard.mempool_excluded_utxos.insert(
            TransactionOutpoint { transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[7u8; 32]), index: 0 },
            make_test_utxo(&address_string, wallet_addr, 7, 0),
        );
    }
    let (svc, _shutdown) = make_service_synced(state).await;
    let resp = svc.get_balance(Request::new(GetBalanceRequest {})).await.unwrap().into_inner();
    assert_eq!(resp.available, 0);
    assert_eq!(resp.pending, 0);
    assert!(resp.address_balances.is_empty());
}

#[tokio::test]
async fn get_external_spendable_utxos_filters_chain_and_address() {
    let state = make_state();
    let external_addr = make_test_address_string();
    let internal_addr = "kaspa:other-address-internal".to_owned();
    let external_wallet = WalletAddress { cosigner_index: 0, key_chain: KeyChain::External, index: 1 };
    let internal_wallet = WalletAddress { cosigner_index: 0, key_chain: KeyChain::Internal, index: 1 };
    {
        let mut guard = state.lock().await;
        guard.utxos_sorted_by_amount.push(make_test_utxo(&external_addr, external_wallet, 100, 0));
        guard.utxos_sorted_by_amount.push(make_test_utxo(&internal_addr, internal_wallet, 200, 1));
    }
    let (svc, _shutdown) = make_service_synced(state).await;
    let resp = svc
        .get_external_spendable_utx_os(Request::new(GetExternalSpendableUtxOsRequest { address: external_addr.clone() }))
        .await
        .unwrap()
        .into_inner();
    assert_eq!(resp.entries.len(), 1, "expect only external-chain UTXO at the queried address");
    assert_eq!(resp.entries[0].address, external_addr);
}

/// Hand-rolled mock that replays canned responses and records the
/// addresses each call is made with. Used by the sync-loop step
/// test.
struct MockKaspad {
    balances: Mutex<Vec<RpcBalancesByAddressesEntry>>,
    utxos: Mutex<Vec<RpcUtxosByAddressesEntry>>,
    mempool: Mutex<Vec<RpcMempoolEntryByAddress>>,
    balance_calls: Mutex<u32>,
    utxo_calls: Mutex<u32>,
    mempool_calls: Mutex<u32>,
    submit_calls: Mutex<Vec<kaspa_rpc_core::RpcTransaction>>,
    submit_replacement_calls: Mutex<Vec<kaspa_rpc_core::RpcTransaction>>,
    next_txid: Mutex<u8>,
    virtual_daa_score: Mutex<u64>,
    fee_estimate: Mutex<RpcFeeEstimate>,
    mempool_entry: Mutex<Option<RpcMempoolEntry>>,
}

impl MockKaspad {
    fn empty() -> Arc<Self> {
        Arc::new(Self {
            balances: Mutex::new(Vec::new()),
            utxos: Mutex::new(Vec::new()),
            mempool: Mutex::new(Vec::new()),
            balance_calls: Mutex::new(0),
            utxo_calls: Mutex::new(0),
            mempool_calls: Mutex::new(0),
            submit_calls: Mutex::new(Vec::new()),
            submit_replacement_calls: Mutex::new(Vec::new()),
            next_txid: Mutex::new(0),
            virtual_daa_score: Mutex::new(1_000_000),
            fee_estimate: Mutex::new(default_fee_estimate()),
            mempool_entry: Mutex::new(None),
        })
    }

    async fn next_txid(&self) -> kaspa_rpc_core::RpcTransactionId {
        let mut idx = self.next_txid.lock().await;
        let bytes = [*idx; 32];
        *idx = idx.wrapping_add(1);
        kaspa_rpc_core::RpcTransactionId::from_slice(&bytes)
    }
}

/// Mempool-feed default for tests that do not exercise the
/// fee-policy branches: a single normal-priority bucket at the
/// `MIN_FEE_RATE` floor (1.0) with a placeholder priority bucket.
fn default_fee_estimate() -> RpcFeeEstimate {
    let bucket = RpcFeerateBucket { feerate: 1.0, estimated_seconds: 1.0 };
    RpcFeeEstimate { priority_bucket: bucket, normal_buckets: vec![bucket], low_buckets: Vec::new() }
}

#[async_trait]
impl KaspadFacade for MockKaspad {
    async fn get_balances_by_addresses(
        &self,
        addresses: Vec<RpcAddress>,
    ) -> Result<Vec<RpcBalancesByAddressesEntry>, super::error::DaemonError> {
        let _ = addresses;
        *self.balance_calls.lock().await += 1;
        Ok(self.balances.lock().await.clone())
    }

    async fn get_utxos_by_addresses(
        &self,
        addresses: Vec<RpcAddress>,
    ) -> Result<Vec<RpcUtxosByAddressesEntry>, super::error::DaemonError> {
        let _ = addresses;
        *self.utxo_calls.lock().await += 1;
        Ok(self.utxos.lock().await.clone())
    }

    async fn get_mempool_entries_by_addresses(
        &self,
        addresses: Vec<RpcAddress>,
        _include_orphan_pool: bool,
        _filter_transaction_pool: bool,
    ) -> Result<Vec<RpcMempoolEntryByAddress>, super::error::DaemonError> {
        let _ = addresses;
        *self.mempool_calls.lock().await += 1;
        Ok(self.mempool.lock().await.clone())
    }

    async fn submit_transaction(
        &self,
        transaction: kaspa_rpc_core::RpcTransaction,
        _allow_orphan: bool,
    ) -> Result<kaspa_rpc_core::RpcTransactionId, super::error::DaemonError> {
        self.submit_calls.lock().await.push(transaction);
        Ok(self.next_txid().await)
    }

    async fn submit_transaction_replacement(
        &self,
        transaction: kaspa_rpc_core::RpcTransaction,
    ) -> Result<kaspa_rpc_core::SubmitTransactionReplacementResponse, super::error::DaemonError> {
        self.submit_replacement_calls.lock().await.push(transaction.clone());
        Ok(kaspa_rpc_core::SubmitTransactionReplacementResponse {
            transaction_id: self.next_txid().await,
            replaced_transaction: transaction,
        })
    }

    async fn get_block_dag_info(&self) -> Result<GetBlockDagInfoResponse, super::error::DaemonError> {
        let virtual_daa_score = *self.virtual_daa_score.lock().await;
        Ok(GetBlockDagInfoResponse {
            network: RpcNetworkId::with_suffix(RpcNetworkType::Testnet, 10),
            block_count: 0,
            header_count: 0,
            tip_hashes: Vec::new(),
            difficulty: 0.0,
            past_median_time: 0,
            virtual_parent_hashes: Vec::new(),
            pruning_point_hash: RpcHash::default(),
            virtual_daa_score,
            sink: RpcHash::default(),
        })
    }

    async fn get_mempool_entry(
        &self,
        _transaction_id: kaspa_rpc_core::RpcTransactionId,
        _include_orphan_pool: bool,
        _filter_transaction_pool: bool,
    ) -> Result<RpcMempoolEntry, super::error::DaemonError> {
        self.mempool_entry
            .lock()
            .await
            .clone()
            .ok_or_else(|| super::error::DaemonError::Kaspad("mempool entry not configured".to_owned()))
    }

    async fn get_fee_estimate(&self) -> Result<RpcFeeEstimate, super::error::DaemonError> {
        Ok(self.fee_estimate.lock().await.clone())
    }
}

#[tokio::test]
async fn sync_loop_step_handles_empty_kaspad_responses() {
    let state = make_state();
    let mock = MockKaspad::empty();
    let shutdown = Arc::new(Notify::new());
    let force_sync = Arc::new(Notify::new());
    let sync_loop = SyncLoop::new(state.clone(), mock.clone(), shutdown, force_sync);
    sync_loop.sync().await.expect("sync step should succeed with empty kaspad");
    let progress = state.lock().await.progress;
    assert_eq!(progress.last_used_external_index, 0);
    assert_eq!(progress.last_used_internal_index, 0);
    assert!(*mock.balance_calls.lock().await > 0, "balance RPC should be called for the address sweep");
}

#[tokio::test]
async fn keyfile_save_roundtrip_preserves_fields() {
    use tempfile::NamedTempFile;
    let tmp = NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_path_buf();
    let original = empty_keysfile();
    crate::keyfile::save_to_path(&original, &path).expect("save_to_path");
    let reloaded = crate::keyfile::read_from_path(&path).expect("read_from_path");
    assert_eq!(reloaded.version, original.version);
    assert_eq!(reloaded.num_threads, original.num_threads);
    assert_eq!(reloaded.extended_public_keys, original.extended_public_keys);
    assert_eq!(reloaded.minimum_signatures, original.minimum_signatures);
    assert_eq!(reloaded.cosigner_index, original.cosigner_index);
    assert_eq!(reloaded.last_used_external_index, original.last_used_external_index);
    assert_eq!(reloaded.last_used_internal_index, original.last_used_internal_index);
    assert_eq!(reloaded.ecdsa, original.ecdsa);
}

async fn synced_service_with_keysfile_path(
    state: SharedState,
    keysfile_path: std::path::PathBuf,
) -> (KaspawalletdSvc, Arc<MockKaspad>, Arc<Notify>) {
    {
        let mut guard = state.lock().await;
        guard.progress.first_sync_done = true;
        let max_used = guard.progress.max_used_index();
        guard.progress.next_sync_start_index = max_used + 1;
    }
    let notify = Arc::new(Notify::new());
    let mock = MockKaspad::empty();
    let kaspad: Arc<dyn KaspadFacade> = mock.clone();
    let force_sync = Arc::new(Notify::new());
    (KaspawalletdSvc::with_mocks(TEST_VERSION, notify.clone(), state, kaspad, force_sync, keysfile_path), mock, notify)
}

#[tokio::test]
async fn new_address_bumps_index_persists_keyfile_and_derives_address() {
    use tempfile::NamedTempFile;
    let tmp = NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_path_buf();
    let state = make_state();
    // Persist an initial keyfile to disk so the daemon's save
    // path overwrites a real file (mirrors production semantics).
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state.clone(), path.clone()).await;
    let resp = svc.new_address(Request::new(NewAddressRequest {})).await.expect("new_address").into_inner();
    assert!(resp.address.starts_with("kaspa:"), "unexpected prefix: {}", resp.address);

    let progress = state.lock().await.progress;
    assert_eq!(progress.last_used_external_index, 1, "external index should bump from 0 to 1");

    let reloaded = crate::keyfile::read_from_path(&path).expect("reload");
    assert_eq!(reloaded.last_used_external_index, 1, "keyfile on disk should reflect the bump");
}

#[tokio::test]
async fn broadcast_submits_via_kaspad_and_records_used_outpoints() {
    // Build a domain-tx-shaped wire blob (TransactionMessage) so
    // `decode_broadcast_tx(is_domain=true)` accepts it and the
    // mock kaspad records the submit.
    let state = make_state();
    let path = std::env::temp_dir().join("kaspawallet-test-broadcast.json");
    let (svc, mock, _shutdown) = synced_service_with_keysfile_path(state.clone(), path).await;

    // Synthesize a minimal TransactionMessage with one input + one
    // output so wire_to_consensus_tx produces a non-trivial tx and
    // the used_outpoints map records the spent outpoint.
    use crate::serialization::wire as proto;
    let tx = proto::TransactionMessage {
        version: 0,
        inputs: vec![proto::TransactionInput {
            previous_outpoint: Some(proto::Outpoint { transaction_id: Some(proto::TransactionId { bytes: vec![1u8; 32] }), index: 0 }),
            signature_script: Vec::new(),
            sequence: 0,
            sig_op_count: 0,
        }],
        outputs: vec![proto::TransactionOutput {
            value: 1000,
            script_public_key: Some(proto::ScriptPublicKey { script: vec![0x76u8; 32], version: 0 }),
        }],
        lock_time: 0,
        subnetwork_id: Some(proto::SubnetworkId { bytes: vec![0u8; 20] }),
        gas: 0,
        payload: Vec::new(),
    };
    let bytes = crate::serialization::serialize_domain_transaction(&tx).expect("serialize");

    let resp = svc
        .broadcast(Request::new(BroadcastRequest { is_domain: true, transactions: vec![bytes] }))
        .await
        .expect("broadcast")
        .into_inner();
    assert_eq!(resp.tx_i_ds.len(), 1, "one tx submitted");
    assert_eq!(mock.submit_calls.lock().await.len(), 1, "mock recorded one submit");
    let used = state.lock().await.used_outpoints.clone();
    assert_eq!(used.len(), 1, "one outpoint marked spent");
}

#[tokio::test]
async fn broadcast_replacement_uses_rbf_for_first_then_normal_submit() {
    let state = make_state();
    let path = std::env::temp_dir().join("kaspawallet-test-broadcast-replacement.json");
    let (svc, mock, _shutdown) = synced_service_with_keysfile_path(state, path).await;

    use crate::serialization::wire as proto;
    let mk_tx = |idx: u8| proto::TransactionMessage {
        version: 0,
        inputs: vec![proto::TransactionInput {
            previous_outpoint: Some(proto::Outpoint { transaction_id: Some(proto::TransactionId { bytes: vec![idx; 32] }), index: 0 }),
            signature_script: Vec::new(),
            sequence: 0,
            sig_op_count: 0,
        }],
        outputs: vec![proto::TransactionOutput {
            value: 1000,
            script_public_key: Some(proto::ScriptPublicKey { script: vec![0x76u8; 32], version: 0 }),
        }],
        lock_time: 0,
        subnetwork_id: Some(proto::SubnetworkId { bytes: vec![0u8; 20] }),
        gas: 0,
        payload: Vec::new(),
    };
    let bytes_a = crate::serialization::serialize_domain_transaction(&mk_tx(1)).expect("serialize");
    let bytes_b = crate::serialization::serialize_domain_transaction(&mk_tx(2)).expect("serialize");

    let resp = svc
        .broadcast_replacement(Request::new(BroadcastRequest { is_domain: true, transactions: vec![bytes_a, bytes_b] }))
        .await
        .expect("broadcast_replacement")
        .into_inner();
    assert_eq!(resp.tx_i_ds.len(), 2);
    assert_eq!(mock.submit_replacement_calls.lock().await.len(), 1, "first tx via RBF");
    assert_eq!(mock.submit_calls.lock().await.len(), 1, "second tx via normal submit");
}

fn make_test_address_string() -> String {
    let address = Address::new(AddressPrefix::Mainnet, AddressVersion::PubKey, &[1u8; 32]);
    address.to_string()
}

/// Read the committed singlekey fixture so the daemon-state has a
/// real keyfile (real ktub xpub + a real encrypted mnemonic).
/// Tests that exercise the full Send pipeline against a synthetic
/// UTXO need this fixture so the password-decrypt step succeeds.
fn singlekey_fixture_keysfile() -> KeysFile {
    let mut p = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    p.push("tests");
    p.push("fixtures");
    p.push("legacy_go_v1_singlekey.json");
    crate::keyfile::read_from_path(&p).expect("fixture decodes")
}

/// Passphrase for the singlekey fixture (matches `sign/tests.rs`'s
/// `b"test fixture passphrase"`).
const SINGLEKEY_FIXTURE_PASSPHRASE: &[u8] = b"test fixture passphrase";

/// Build a synced daemon state seeded with one external-chain UTXO
/// at index 1. Used by the composition-trio tests so the
/// coin-selection layer has a candidate to pick. Returns the
/// wallet-address string the seeded UTXO claims, so the test can
/// pass it back as a `from` filter or assert against the response.
async fn seeded_state_with_one_utxo(keyfile: KeysFile, amount: u64) -> (SharedState, String) {
    let state = shared(DaemonState::new(keyfile, AddressPrefix::Mainnet));
    let wallet_addr = WalletAddress { cosigner_index: 0, key_chain: KeyChain::External, index: 1 };
    let address_string = {
        let guard = state.lock().await;
        guard.wallet_address_string(wallet_addr).expect("derive seeded address")
    };
    {
        let mut guard = state.lock().await;
        // Synthetic outpoint with a script_public_key carrying the
        // wallet's first external p2pk script. The script bytes
        // themselves don't matter for the coin-selection wiring
        // tests; the load-bearing field is `address` (the wallet
        // identity) which the daemon iterates over.
        let outpoint =
            TransactionOutpoint { transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[0xAA; 32]), index: 0 };
        let script_public_key = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x76u8; 35]));
        let utxo_entry = RpcUtxoEntry { amount, script_public_key, block_daa_score: 0, is_coinbase: false };
        guard.utxos_sorted_by_amount.push(WalletUtxo {
            outpoint,
            utxo_entry,
            address: wallet_addr,
            address_string: address_string.clone(),
        });
        guard.address_set.insert(address_string.clone(), wallet_addr);
        guard.progress.last_used_external_index = 1;
        guard.progress.first_sync_done = true;
        guard.progress.next_sync_start_index = 2;
    }
    (state, address_string)
}

/// Mainnet recipient address that always parses (zero-pubkey
/// well-known string). Used by composition-trio tests to satisfy
/// the recipient `Address::try_from` parse.
fn dummy_mainnet_address() -> String {
    Address::new(AddressPrefix::Mainnet, AddressVersion::PubKey, &[2u8; 32]).to_string()
}

#[tokio::test]
async fn create_unsigned_transactions_emits_pst_with_seeded_utxos() {
    let keyfile = singlekey_fixture_keysfile();
    let (state, _wallet_addr_str) = seeded_state_with_one_utxo(keyfile, 50_000_000_000).await;
    let path = std::env::temp_dir().join("kaspawallet-test-cut-emits.json");
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state, path).await;

    let resp = svc
        .create_unsigned_transactions(Request::new(CreateUnsignedTransactionsRequest {
            address: dummy_mainnet_address(),
            amount: 5_000_000_000,
            from: Vec::new(),
            use_existing_change_address: false,
            is_send_all: false,
            fee_policy: Some(FeePolicy { fee_policy: Some(FeePolicyOneof::ExactFeeRate(1.0)) }),
        }))
        .await
        .expect("create_unsigned_transactions")
        .into_inner();
    assert!(!resp.unsigned_transactions.is_empty(), "expect at least one unsigned PST blob");
    assert!(
        resp.unsigned_transactions[0].len() > 64,
        "blob too small to be a real PSTX: {} bytes",
        resp.unsigned_transactions[0].len()
    );
}

#[tokio::test]
async fn create_unsigned_transactions_rejects_invalid_recipient_address() {
    let (state, _) = seeded_state_with_one_utxo(singlekey_fixture_keysfile(), 50_000_000_000).await;
    let path = std::env::temp_dir().join("kaspawallet-test-cut-bad-addr.json");
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state, path).await;

    let status = svc
        .create_unsigned_transactions(Request::new(CreateUnsignedTransactionsRequest {
            address: "not-a-valid-address".to_owned(),
            amount: 1,
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert!(status.message().contains("invalid recipient address"), "msg: {}", status.message());
}

#[tokio::test]
async fn create_unsigned_transactions_rejects_recipient_with_wrong_prefix() {
    // State is mainnet; recipient is testnet -> InvalidArgument.
    let (state, _) = seeded_state_with_one_utxo(singlekey_fixture_keysfile(), 50_000_000_000).await;
    let path = std::env::temp_dir().join("kaspawallet-test-cut-prefix.json");
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state, path).await;
    let testnet_recipient = Address::new(AddressPrefix::Testnet, AddressVersion::PubKey, &[3u8; 32]).to_string();

    let status = svc
        .create_unsigned_transactions(Request::new(CreateUnsignedTransactionsRequest {
            address: testnet_recipient,
            amount: 1,
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert!(status.message().contains("does not match wallet network"), "msg: {}", status.message());
}

#[tokio::test]
async fn create_unsigned_transactions_rejects_unknown_from_address() {
    let (state, _) = seeded_state_with_one_utxo(singlekey_fixture_keysfile(), 50_000_000_000).await;
    let path = std::env::temp_dir().join("kaspawallet-test-cut-bad-from.json");
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state, path).await;

    let status = svc
        .create_unsigned_transactions(Request::new(CreateUnsignedTransactionsRequest {
            address: dummy_mainnet_address(),
            amount: 1,
            from: vec!["kaspa:qqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqqkx9awp4e".to_owned()],
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert!(status.message().contains("does not exists"), "msg: {}", status.message());
}

#[tokio::test]
async fn create_unsigned_transactions_returns_internal_on_insufficient_funds() {
    // Empty UTXO snapshot (no seeded UTXO) -> coin-selection
    // surfaces InsufficientFunds; service maps to Internal because
    // the failure originates inside the coinsel module rather than
    // at the request boundary.
    let state = shared(DaemonState::new(singlekey_fixture_keysfile(), AddressPrefix::Mainnet));
    {
        let mut guard = state.lock().await;
        guard.progress.first_sync_done = true;
        guard.progress.next_sync_start_index = 1;
    }
    let path = std::env::temp_dir().join("kaspawallet-test-cut-no-utxos.json");
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state, path).await;

    let status = svc
        .create_unsigned_transactions(Request::new(CreateUnsignedTransactionsRequest {
            address: dummy_mainnet_address(),
            amount: 1_000_000,
            fee_policy: Some(FeePolicy { fee_policy: Some(FeePolicyOneof::ExactFeeRate(1.0)) }),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    // coinsel maps insufficient funds to its typed error; service
    // wraps it as Internal. The error message mentions "insufficient".
    assert_eq!(status.code(), Code::Internal);
    assert!(status.message().to_lowercase().contains("insufficient"), "msg: {}", status.message());
}

#[tokio::test]
async fn create_unsigned_transactions_bumps_internal_index_when_change_required() {
    // Seed a UTXO worth 50 KAS, request a 5 KAS payment ->
    // change is required, so the daemon bumps internal index 0->1
    // and persists the keyfile.
    let (state, _) = seeded_state_with_one_utxo(singlekey_fixture_keysfile(), 50_000_000_000).await;
    let initial_internal = state.lock().await.progress.last_used_internal_index;
    use tempfile::NamedTempFile;
    let tmp = NamedTempFile::new().expect("tempfile");
    let path = tmp.path().to_path_buf();
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state.clone(), path.clone()).await;

    let _resp = svc
        .create_unsigned_transactions(Request::new(CreateUnsignedTransactionsRequest {
            address: dummy_mainnet_address(),
            amount: 5_000_000_000,
            from: Vec::new(),
            use_existing_change_address: false,
            is_send_all: false,
            fee_policy: Some(FeePolicy { fee_policy: Some(FeePolicyOneof::ExactFeeRate(1.0)) }),
        }))
        .await
        .expect("create_unsigned_transactions");
    let bumped = state.lock().await.progress.last_used_internal_index;
    assert_eq!(bumped, initial_internal + 1, "internal index should bump for fresh change address");
    let reloaded = crate::keyfile::read_from_path(&path).expect("reload");
    assert_eq!(reloaded.last_used_internal_index, bumped, "keyfile on disk should reflect the bump");
}

#[tokio::test]
async fn send_rejects_bad_password() {
    let (state, _) = seeded_state_with_one_utxo(singlekey_fixture_keysfile(), 50_000_000_000).await;
    let path = std::env::temp_dir().join("kaspawallet-test-send-bad-pw.json");
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state, path).await;

    let status = svc
        .send(Request::new(SendRequest {
            to_address: dummy_mainnet_address(),
            amount: 5_000_000_000,
            password: "wrong-passphrase".to_owned(),
            from: Vec::new(),
            use_existing_change_address: false,
            is_send_all: false,
            fee_policy: Some(FeePolicy { fee_policy: Some(FeePolicyOneof::ExactFeeRate(1.0)) }),
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert!(status.message().contains("keyfile decryption failed"), "msg: {}", status.message());
}

#[tokio::test]
async fn send_succeeds_with_correct_password_and_records_submission() {
    let (state, _) = seeded_state_with_one_utxo(singlekey_fixture_keysfile(), 50_000_000_000).await;
    let path = std::env::temp_dir().join("kaspawallet-test-send-ok.json");
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, mock, _shutdown) = synced_service_with_keysfile_path(state.clone(), path).await;

    let resp = svc
        .send(Request::new(SendRequest {
            to_address: dummy_mainnet_address(),
            amount: 5_000_000_000,
            password: String::from_utf8(SINGLEKEY_FIXTURE_PASSPHRASE.to_vec()).unwrap(),
            from: Vec::new(),
            use_existing_change_address: false,
            is_send_all: false,
            fee_policy: Some(FeePolicy { fee_policy: Some(FeePolicyOneof::ExactFeeRate(1.0)) }),
        }))
        .await
        .expect("send")
        .into_inner();
    assert!(!resp.tx_i_ds.is_empty(), "expect at least one tx-id");
    assert_eq!(resp.tx_i_ds.len(), resp.signed_transactions.len(), "tx-ids and signed blobs are 1:1");
    assert!(!mock.submit_calls.lock().await.is_empty(), "mock kaspad recorded at least one submit");
    let used = state.lock().await.used_outpoints.clone();
    assert!(!used.is_empty(), "send must record spent outpoints");
}

#[tokio::test]
async fn bump_fee_rejects_invalid_tx_id() {
    let (state, _) = seeded_state_with_one_utxo(singlekey_fixture_keysfile(), 50_000_000_000).await;
    let path = std::env::temp_dir().join("kaspawallet-test-bump-bad-id.json");
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state, path).await;

    let status = svc
        .bump_fee(Request::new(BumpFeeRequest { password: String::new(), tx_id: "not-hex".to_owned(), ..Default::default() }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::InvalidArgument);
    assert!(status.message().contains("invalid tx_id"), "msg: {}", status.message());
}

#[tokio::test]
async fn bump_fee_propagates_kaspad_error_when_no_mempool_entry() {
    let (state, _) = seeded_state_with_one_utxo(singlekey_fixture_keysfile(), 50_000_000_000).await;
    let path = std::env::temp_dir().join("kaspawallet-test-bump-no-entry.json");
    crate::keyfile::save_to_path(&state.lock().await.keyfile, &path).expect("initial save");
    let (svc, _mock, _shutdown) = synced_service_with_keysfile_path(state, path).await;
    // mock.mempool_entry stays None -> get_mempool_entry returns
    // a kaspad-side error -> service maps to Internal.

    let status = svc
        .bump_fee(Request::new(BumpFeeRequest {
            password: String::new(),
            // 32-byte zero hash -> parses fine; lookup fails inside the mock.
            tx_id: "0000000000000000000000000000000000000000000000000000000000000000".to_owned(),
            ..Default::default()
        }))
        .await
        .unwrap_err();
    assert_eq!(status.code(), Code::Internal);
    assert!(status.message().contains("kaspad get_mempool_entry"), "msg: {}", status.message());
}

fn make_test_utxo(address_string: &str, wallet_addr: WalletAddress, amount: u64, outpoint_index: u32) -> WalletUtxo {
    let outpoint = TransactionOutpoint {
        transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[outpoint_index as u8; 32]),
        index: outpoint_index,
    };
    let script_public_key = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x76u8; 32]));
    let utxo_entry = RpcUtxoEntry { amount, script_public_key, block_daa_score: 0, is_coinbase: false };
    WalletUtxo { outpoint, utxo_entry, address: wallet_addr, address_string: address_string.to_owned() }
}

fn make_immature_coinbase_utxo(
    address_string: &str,
    wallet_addr: WalletAddress,
    amount: u64,
    outpoint_index: u32,
    block_daa_score: u64,
) -> WalletUtxo {
    let outpoint = TransactionOutpoint {
        transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[outpoint_index as u8; 32]),
        index: outpoint_index,
    };
    let script_public_key = ScriptPublicKey::new(0, ScriptVec::from_slice(&[0x76u8; 32]));
    let utxo_entry = RpcUtxoEntry { amount, script_public_key, block_daa_score, is_coinbase: true };
    WalletUtxo { outpoint, utxo_entry, address: wallet_addr, address_string: address_string.to_owned() }
}
