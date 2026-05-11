//! Narrow facade over the kaspad gRPC RPC surface the wallet
//! daemon depends on. The trait abstracts just the methods the
//! daemon's sync loop and RPC handlers need, which keeps the test
//! mock small and isolates the daemon from the broader
//! `kaspa_rpc_core::api::rpc::RpcApi` surface.
//!
//! The production implementation wraps
//! `kaspa_grpc_client::GrpcClient`; tests use a hand-rolled mock
//! that records calls and replays canned responses.
//!
//! As the slice expands beyond the view RPCs (next sub-slice:
//! transaction construction + broadcast), the trait widens to
//! cover `submit_transaction` and
//! `submit_transaction_replacement`. The current trait surface
//! is the subset the view-only RPCs and the sync loop consume.

use std::sync::Arc;

use async_trait::async_trait;
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::api::rpc::RpcApi;
use kaspa_rpc_core::{
    GetBlockDagInfoResponse, RpcAddress, RpcBalancesByAddressesEntry, RpcFeeEstimate, RpcMempoolEntry, RpcMempoolEntryByAddress,
    RpcTransaction, RpcTransactionId, RpcUtxosByAddressesEntry, SubmitTransactionReplacementResponse,
};

use super::error::DaemonError;

/// Wallet-daemon-facing slice of the kaspad RPC surface. Owned by
/// `DaemonState` and consumed by the sync loop.
#[async_trait]
pub trait KaspadFacade: Send + Sync {
    /// Reports balances per address. Used by the sync loop to
    /// detect address usage during the initial scan and the
    /// incremental far-address sweep.
    async fn get_balances_by_addresses(&self, addresses: Vec<RpcAddress>) -> Result<Vec<RpcBalancesByAddressesEntry>, DaemonError>;

    /// Reports the full UTXO set across the supplied addresses.
    /// Used by the sync loop to populate the daemon's
    /// amount-sorted UTXO snapshot.
    async fn get_utxos_by_addresses(&self, addresses: Vec<RpcAddress>) -> Result<Vec<RpcUtxosByAddressesEntry>, DaemonError>;

    /// Reports mempool transactions involving the supplied
    /// addresses. Used by the sync loop to mark UTXOs spent in
    /// the mempool but not yet in consensus, so the daemon's
    /// coin-selection avoids them.
    async fn get_mempool_entries_by_addresses(
        &self,
        addresses: Vec<RpcAddress>,
        include_orphan_pool: bool,
        filter_transaction_pool: bool,
    ) -> Result<Vec<RpcMempoolEntryByAddress>, DaemonError>;

    /// Submit a signed transaction to the kaspad mempool. Returns
    /// the consensus transaction-ID kaspad accepted.
    async fn submit_transaction(&self, transaction: RpcTransaction, allow_orphan: bool) -> Result<RpcTransactionId, DaemonError>;

    /// Submit a Replace-By-Fee transaction to kaspad. Returns the
    /// new transaction-ID and (per the upstream API) the previously
    /// accepted transaction the replacement supplanted.
    async fn submit_transaction_replacement(
        &self,
        transaction: RpcTransaction,
    ) -> Result<SubmitTransactionReplacementResponse, DaemonError>;

    /// Reports current DAG state. The wallet daemon consumes
    /// `virtual_daa_score` for the coinbase-maturity gate inside
    /// the coin-selection loop (mirrors Go `GetBlockDAGInfo` calls
    /// at `cmd/kaspawallet/daemon/server/create_unsigned_transaction.go:164`
    /// and `bump_fee.go:62`).
    async fn get_block_dag_info(&self) -> Result<GetBlockDagInfoResponse, DaemonError>;

    /// Reports a mempool entry by transaction-id. Used by
    /// `BumpFee` to recover the original transaction body and its
    /// committed fee. Mirrors Go `GetMempoolEntry` at
    /// `cmd/kaspawallet/daemon/server/bump_fee.go:18`.
    async fn get_mempool_entry(
        &self,
        transaction_id: RpcTransactionId,
        include_orphan_pool: bool,
        filter_transaction_pool: bool,
    ) -> Result<RpcMempoolEntry, DaemonError>;

    /// Reports kaspad's current feerate buckets. Used by the
    /// daemon's `calculate_fee_limits` helper for every FeePolicy
    /// branch except `ExactFeeRate`. Mirrors Go `GetFeeEstimate`
    /// usage at `cmd/kaspawallet/daemon/server/create_unsigned_transaction.go:58,67,74`.
    async fn get_fee_estimate(&self) -> Result<RpcFeeEstimate, DaemonError>;
}

/// Production facade: wraps a connected `kaspa_grpc_client::GrpcClient`.
pub struct GrpcKaspadFacade {
    inner: Arc<GrpcClient>,
}

impl GrpcKaspadFacade {
    /// Take ownership of a connected gRPC client. The caller dials
    /// and starts the client beforehand; this wrapper does not
    /// manage the connection lifecycle.
    pub fn new(client: Arc<GrpcClient>) -> Self {
        Self { inner: client }
    }
}

#[async_trait]
impl KaspadFacade for GrpcKaspadFacade {
    async fn get_balances_by_addresses(&self, addresses: Vec<RpcAddress>) -> Result<Vec<RpcBalancesByAddressesEntry>, DaemonError> {
        self.inner.get_balances_by_addresses(addresses).await.map_err(|e| DaemonError::Kaspad(e.to_string()))
    }

    async fn get_utxos_by_addresses(&self, addresses: Vec<RpcAddress>) -> Result<Vec<RpcUtxosByAddressesEntry>, DaemonError> {
        self.inner.get_utxos_by_addresses(addresses).await.map_err(|e| DaemonError::Kaspad(e.to_string()))
    }

    async fn get_mempool_entries_by_addresses(
        &self,
        addresses: Vec<RpcAddress>,
        include_orphan_pool: bool,
        filter_transaction_pool: bool,
    ) -> Result<Vec<RpcMempoolEntryByAddress>, DaemonError> {
        self.inner
            .get_mempool_entries_by_addresses(addresses, include_orphan_pool, filter_transaction_pool)
            .await
            .map_err(|e| DaemonError::Kaspad(e.to_string()))
    }

    async fn submit_transaction(&self, transaction: RpcTransaction, allow_orphan: bool) -> Result<RpcTransactionId, DaemonError> {
        self.inner.submit_transaction(transaction, allow_orphan).await.map_err(|e| DaemonError::Kaspad(e.to_string()))
    }

    async fn submit_transaction_replacement(
        &self,
        transaction: RpcTransaction,
    ) -> Result<SubmitTransactionReplacementResponse, DaemonError> {
        self.inner.submit_transaction_replacement(transaction).await.map_err(|e| DaemonError::Kaspad(e.to_string()))
    }

    async fn get_block_dag_info(&self) -> Result<GetBlockDagInfoResponse, DaemonError> {
        self.inner.get_block_dag_info().await.map_err(|e| DaemonError::Kaspad(e.to_string()))
    }

    async fn get_mempool_entry(
        &self,
        transaction_id: RpcTransactionId,
        include_orphan_pool: bool,
        filter_transaction_pool: bool,
    ) -> Result<RpcMempoolEntry, DaemonError> {
        self.inner
            .get_mempool_entry(transaction_id, include_orphan_pool, filter_transaction_pool)
            .await
            .map_err(|e| DaemonError::Kaspad(e.to_string()))
    }

    async fn get_fee_estimate(&self) -> Result<RpcFeeEstimate, DaemonError> {
        self.inner.get_fee_estimate().await.map_err(|e| DaemonError::Kaspad(e.to_string()))
    }
}
