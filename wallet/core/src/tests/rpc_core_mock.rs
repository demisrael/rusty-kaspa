use crate::imports::*;

use async_channel::{Receiver, unbounded};
use async_trait::async_trait;
use kaspa_notify::events::EVENT_TYPE_ARRAY;
use kaspa_notify::listener::{ListenerId, ListenerLifespan};
use kaspa_notify::notifier::{Notifier, Notify};
use kaspa_notify::scope::Scope;
use kaspa_notify::subscription::context::SubscriptionContext;
use kaspa_notify::subscription::{MutationPolicies, UtxosChangedMutationPolicy};
use kaspa_rpc_core::api::ctl::RpcCtl;
use kaspa_rpc_core::api::ops::{RPC_API_REVISION, RPC_API_VERSION};
use kaspa_rpc_core::{RpcResult, notify::connection::ChannelConnection};
use kaspa_rpc_core::{api::connection::DynRpcConnection, api::rpc::RpcApi, *};
use std::sync::Arc;

pub type RpcCoreNotifier = Notifier<Notification, ChannelConnection>;

impl From<Arc<RpcCoreMock>> for Rpc {
    fn from(rpc_mock: Arc<RpcCoreMock>) -> Self {
        Self::new(rpc_mock.clone(), rpc_mock.ctl.clone())
    }
}

pub struct RpcCoreMock {
    ctl: RpcCtl,
    core_notifier: Arc<RpcCoreNotifier>,
    _sync_receiver: Receiver<()>,
    /// Canned per-address balances surfaced via `get_balances_by_addresses_call`.
    /// `None` (entry absent) keeps the default `Option<u64>::None` semantics
    /// (BIP-44 section 6 "no transactions" - treated as zero by the gap-limit walk).
    /// `Some(v)` returns `Some(v)` to the caller.
    balances: std::sync::Mutex<std::collections::HashMap<RpcAddress, Option<u64>>>,
    /// Counter incremented on every `get_balances_by_addresses_call` invocation.
    /// Tests pin the gap-limit termination by reading the counter against the
    /// expected candidate-account walk count.
    balance_call_count: std::sync::atomic::AtomicU64,
    /// Batch sizes observed by `get_utxos_by_addresses_call`.
    utxo_address_batch_sizes: std::sync::Mutex<Vec<usize>>,
}

impl RpcCoreMock {
    pub fn new() -> Self {
        let (sync_sender, sync_receiver) = unbounded();
        let policies = MutationPolicies::new(UtxosChangedMutationPolicy::AddressSet);
        let core_notifier: Arc<RpcCoreNotifier> = Arc::new(Notifier::with_sync(
            "rpc-core",
            EVENT_TYPE_ARRAY[..].into(),
            vec![],
            vec![],
            SubscriptionContext::new(),
            10,
            policies,
            Some(sync_sender),
        ));
        Self {
            core_notifier,
            _sync_receiver: sync_receiver,
            ctl: RpcCtl::new(),
            balances: std::sync::Mutex::new(std::collections::HashMap::new()),
            balance_call_count: std::sync::atomic::AtomicU64::new(0),
            utxo_address_batch_sizes: std::sync::Mutex::new(Vec::new()),
        }
    }

    /// Pin a per-address balance for the next `get_balances_by_addresses_call`
    /// response. `Some(v)` returns `Some(v)`; addresses not pinned default to
    /// `None` ("no transactions" per BIP-44 section 6).
    pub fn set_balance(&self, address: RpcAddress, balance: u64) {
        self.balances.lock().unwrap().insert(address, Some(balance));
    }

    /// Return the cumulative number of `get_balances_by_addresses_call`
    /// invocations since mock construction.
    pub fn balance_call_count(&self) -> u64 {
        self.balance_call_count.load(std::sync::atomic::Ordering::SeqCst)
    }

    pub fn utxo_request_sizes(&self) -> Vec<usize> {
        self.utxo_address_batch_sizes.lock().unwrap().clone()
    }

    pub fn core_notifier(&self) -> Arc<RpcCoreNotifier> {
        self.core_notifier.clone()
    }

    #[allow(dead_code)]
    pub fn notify_new_block_template(&self) -> kaspa_notify::error::Result<()> {
        let notification = Notification::NewBlockTemplate(NewBlockTemplateNotification {});
        self.core_notifier.notify(notification)
    }

    #[allow(dead_code)]
    pub async fn notify_complete(&self) {
        assert!(self._sync_receiver.recv().await.is_ok(), "the notifier sync channel is unexpectedly empty and closed");
    }

    pub fn start(&self) {
        self.core_notifier.clone().start();
    }

    pub async fn join(&self) {
        self.core_notifier.join().await.expect("core notifier shutdown")
    }

    // ---

    pub fn ctl(&self) -> RpcCtl {
        self.ctl.clone()
    }
}

impl Default for RpcCoreMock {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait]
impl RpcApi for RpcCoreMock {
    // This fn needs to succeed while the client connects
    async fn get_info_call(&self, _connection: Option<&DynRpcConnection>, _request: GetInfoRequest) -> RpcResult<GetInfoResponse> {
        Ok(GetInfoResponse {
            p2p_id: "wallet-mock".to_string(),
            mempool_size: 1234,
            server_version: "mock".to_string(),
            is_utxo_indexed: false,
            is_synced: false,
            has_notify_command: false,
            has_message_id: false,
        })
    }

    async fn ping_call(&self, _connection: Option<&DynRpcConnection>, _request: PingRequest) -> RpcResult<PingResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_metrics_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetMetricsRequest,
    ) -> RpcResult<GetMetricsResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_connections_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetConnectionsRequest,
    ) -> RpcResult<GetConnectionsResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_server_info_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetServerInfoRequest,
    ) -> RpcResult<GetServerInfoResponse> {
        Ok(GetServerInfoResponse {
            rpc_api_version: RPC_API_VERSION,
            rpc_api_revision: RPC_API_REVISION,
            server_version: "wallet-mock".to_string(),
            network_id: NetworkId::with_suffix(NetworkType::Testnet, 10),
            has_utxo_index: true,
            is_synced: true,
            virtual_daa_score: 1,
        })
    }

    async fn get_system_info_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetSystemInfoRequest,
    ) -> RpcResult<GetSystemInfoResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_sync_status_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetSyncStatusRequest,
    ) -> RpcResult<GetSyncStatusResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_current_network_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetCurrentNetworkRequest,
    ) -> RpcResult<GetCurrentNetworkResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn submit_block_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: SubmitBlockRequest,
    ) -> RpcResult<SubmitBlockResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_block_template_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetBlockTemplateRequest,
    ) -> RpcResult<GetBlockTemplateResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_peer_addresses_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetPeerAddressesRequest,
    ) -> RpcResult<GetPeerAddressesResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_sink_call(&self, _connection: Option<&DynRpcConnection>, _request: GetSinkRequest) -> RpcResult<GetSinkResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_mempool_entry_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetMempoolEntryRequest,
    ) -> RpcResult<GetMempoolEntryResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_mempool_entries_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetMempoolEntriesRequest,
    ) -> RpcResult<GetMempoolEntriesResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_connected_peer_info_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetConnectedPeerInfoRequest,
    ) -> RpcResult<GetConnectedPeerInfoResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn submit_transaction_replacement_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: SubmitTransactionReplacementRequest,
    ) -> RpcResult<SubmitTransactionReplacementResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn add_peer_call(&self, _connection: Option<&DynRpcConnection>, _request: AddPeerRequest) -> RpcResult<AddPeerResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn submit_transaction_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: SubmitTransactionRequest,
    ) -> RpcResult<SubmitTransactionResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_block_call(&self, _connection: Option<&DynRpcConnection>, _request: GetBlockRequest) -> RpcResult<GetBlockResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_seq_commit_lane_proof_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetSeqCommitLaneProofRequest,
    ) -> RpcResult<GetSeqCommitLaneProofResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_subnetwork_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetSubnetworkRequest,
    ) -> RpcResult<GetSubnetworkResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_virtual_chain_from_block_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetVirtualChainFromBlockRequest,
    ) -> RpcResult<GetVirtualChainFromBlockResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_blocks_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetBlocksRequest,
    ) -> RpcResult<GetBlocksResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_block_count_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetBlockCountRequest,
    ) -> RpcResult<GetBlockCountResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_block_dag_info_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetBlockDagInfoRequest,
    ) -> RpcResult<GetBlockDagInfoResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn resolve_finality_conflict_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: ResolveFinalityConflictRequest,
    ) -> RpcResult<ResolveFinalityConflictResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn shutdown_call(&self, _connection: Option<&DynRpcConnection>, _request: ShutdownRequest) -> RpcResult<ShutdownResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_headers_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetHeadersRequest,
    ) -> RpcResult<GetHeadersResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_balance_by_address_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetBalanceByAddressRequest,
    ) -> RpcResult<GetBalanceByAddressResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_balances_by_addresses_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetBalancesByAddressesRequest,
    ) -> RpcResult<GetBalancesByAddressesResponse> {
        self.balance_call_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        let cache = self.balances.lock().unwrap();
        let entries = request
            .addresses
            .into_iter()
            .map(|address| {
                let balance = cache.get(&address).copied().unwrap_or(None);
                RpcBalancesByAddressesEntry { address, balance }
            })
            .collect();
        Ok(GetBalancesByAddressesResponse { entries })
    }

    async fn get_utxos_by_addresses_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        request: GetUtxosByAddressesRequest,
    ) -> RpcResult<GetUtxosByAddressesResponse> {
        self.utxo_address_batch_sizes.lock().unwrap().push(request.addresses.len());
        Ok(GetUtxosByAddressesResponse::new(Vec::new()))
    }

    async fn get_sink_blue_score_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetSinkBlueScoreRequest,
    ) -> RpcResult<GetSinkBlueScoreResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn ban_call(&self, _connection: Option<&DynRpcConnection>, _request: BanRequest) -> RpcResult<BanResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn unban_call(&self, _connection: Option<&DynRpcConnection>, _request: UnbanRequest) -> RpcResult<UnbanResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn estimate_network_hashes_per_second_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: EstimateNetworkHashesPerSecondRequest,
    ) -> RpcResult<EstimateNetworkHashesPerSecondResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_mempool_entries_by_addresses_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetMempoolEntriesByAddressesRequest,
    ) -> RpcResult<GetMempoolEntriesByAddressesResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_coin_supply_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetCoinSupplyRequest,
    ) -> RpcResult<GetCoinSupplyResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_daa_score_timestamp_estimate_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetDaaScoreTimestampEstimateRequest,
    ) -> RpcResult<GetDaaScoreTimestampEstimateResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_fee_estimate_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetFeeEstimateRequest,
    ) -> RpcResult<GetFeeEstimateResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_fee_estimate_experimental_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetFeeEstimateExperimentalRequest,
    ) -> RpcResult<GetFeeEstimateExperimentalResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_current_block_color_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetCurrentBlockColorRequest,
    ) -> RpcResult<GetCurrentBlockColorResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_block_reward_info_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetBlockRewardInfoRequest,
    ) -> RpcResult<GetBlockRewardInfoResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_utxo_return_address_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetUtxoReturnAddressRequest,
    ) -> RpcResult<GetUtxoReturnAddressResponse> {
        Err(RpcError::NotImplemented)
    }

    async fn get_virtual_chain_from_block_v2_call(
        &self,
        _connection: Option<&DynRpcConnection>,
        _request: GetVirtualChainFromBlockV2Request,
    ) -> RpcResult<GetVirtualChainFromBlockV2Response> {
        Err(RpcError::NotImplemented)
    }

    // ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
    // Notification API

    fn register_new_listener(&self, connection: ChannelConnection) -> ListenerId {
        self.core_notifier.register_new_listener(connection, ListenerLifespan::Dynamic)
    }

    async fn unregister_listener(&self, id: ListenerId) -> RpcResult<()> {
        self.core_notifier.unregister_listener(id)?;
        Ok(())
    }

    async fn start_notify(&self, id: ListenerId, scope: Scope) -> RpcResult<()> {
        self.core_notifier.try_start_notify(id, scope)?;
        Ok(())
    }

    async fn stop_notify(&self, id: ListenerId, scope: Scope) -> RpcResult<()> {
        self.core_notifier.try_stop_notify(id, scope)?;
        Ok(())
    }
}
