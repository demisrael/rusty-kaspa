//! Daemon runtime -- listener binding, kaspad dialing, sync-loop
//! spawn, tonic server wiring, and shutdown plumbing.
//!
//! Two public entry points are exposed:
//!
//! - [`start_daemon`] -- the CLI's `start-daemon` entry. Loads the
//!   keyfile, dials kaspad, builds the shared daemon state,
//!   spawns the background sync loop, binds the TCP listener, and
//!   serves until SIGINT/SIGTERM or an in-process `Shutdown` RPC
//!   fires. This is the production path.
//! - [`serve_with_listener`] -- accepts an already-bound
//!   `tokio::net::TcpListener` and a caller-supplied
//!   `ShutdownTrigger`. Used by integration tests to bind to an
//!   ephemeral port (`127.0.0.1:0`), observe the resolved port,
//!   and drive the shutdown explicitly. Does NOT spawn the sync
//!   loop or dial kaspad; tests inject any sync-loop / state
//!   construction directly.
//!
//! The TCP listener is configured via `tonic::transport::Server`'s
//! `serve_with_incoming_shutdown` path. The graceful-stop window
//! is 2 seconds.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use kaspa_addresses::Prefix as AddressPrefix;
use kaspa_grpc_client::GrpcClient;
use tokio::net::TcpListener;
use tokio::sync::Notify;
use tokio_stream::wrappers::TcpListenerStream;
use tonic::transport::Server;

use super::error::DaemonError;
use super::kaspad::GrpcKaspadFacade;
use super::keysfile_lock;
use super::pb::kaspawalletd_server::KaspawalletdServer;
use super::service::KaspawalletdSvc;
use super::state::{DaemonState, shared};
use super::sync::SyncLoop;
use crate::keyfile;

/// Maximum send-message size used by the daemon gRPC server.
pub const MAX_DAEMON_SEND_MSG_SIZE: usize = 100_000_000;

/// Graceful-shutdown timeout.
pub const GRACEFUL_STOP_TIMEOUT: Duration = Duration::from_secs(2);

/// Caller-supplied shutdown signal. Used by integration tests to
/// drive shutdown deterministically without relying on OS signals.
/// The production `start_daemon` path constructs its own internal
/// shutdown future from `tokio::signal::ctrl_c` and the service's
/// `Shutdown`-RPC notification, so callers of `start_daemon` do
/// not need to provide one.
pub struct ShutdownTrigger {
    notify: Arc<Notify>,
}

impl ShutdownTrigger {
    /// Construct a fresh trigger and the notification handle the
    /// service shares with the runtime.
    pub fn new() -> (Self, Arc<Notify>) {
        let notify = Arc::new(Notify::new());
        (Self { notify: notify.clone() }, notify)
    }

    /// Fire the shutdown signal. The associated daemon future
    /// exits cleanly within `GRACEFUL_STOP_TIMEOUT`.
    ///
    /// `notify_one` stores a permit when no waiter is currently
    /// registered, so a `fire()` that races ahead of the
    /// server-side shutdown future still terminates the daemon at
    /// the next poll.
    pub fn fire(&self) {
        self.notify.notify_one();
    }

    /// Borrow the internal notification handle. Service handlers
    /// receive a clone of this `Arc<Notify>` so the `Shutdown` RPC
    /// fires the same signal an external `fire()` call would.
    pub fn handle(&self) -> Arc<Notify> {
        self.notify.clone()
    }
}

impl Default for ShutdownTrigger {
    fn default() -> Self {
        Self::new().0
    }
}

/// Options that the CLI's `start-daemon` subcommand passes into
/// the daemon runtime.
#[derive(Debug, Clone)]
pub struct ServeOptions {
    /// `host:port` style listener address (`localhost:8082` by
    /// default).
    pub listen: String,
    /// Resolved on-disk path to the keyfile. The CLI resolves this
    /// via the keysource default-path resolver before constructing
    /// `ServeOptions`.
    pub keysfile_path: PathBuf,
    /// kaspad gRPC endpoint. May be a bare authority (`host:port`)
    /// or a full URL with `grpc://` scheme.
    pub rpcserver: String,
    /// Address prefix derived from the operator-selected network.
    pub address_prefix: AddressPrefix,
    /// Reported binary version string. Surfaced via the `GetVersion`
    /// RPC.
    pub version: String,
}

/// CLI entry point. Loads the keyfile, dials kaspad, builds the
/// shared state, spawns the sync loop, binds the listener, and
/// serves the gRPC surface until SIGINT/SIGTERM or a `Shutdown`
/// RPC fires.
pub async fn start_daemon(opts: ServeOptions) -> Result<(), DaemonError> {
    // Acquire the exclusive keyfile lock BEFORE binding the
    // listener or reading the keyfile: two daemons against the
    // same keyfile would race the JSON file on `save_to_path`
    // otherwise. The guard releases the OS lock on drop at
    // function exit.
    let _keysfile_guard = keysfile_lock::acquire(&opts.keysfile_path)?;
    let listener = bind_listener(&opts.listen).await?;
    let keyfile = keyfile::read_from_path(&opts.keysfile_path)?;
    let state = shared(DaemonState::new(keyfile, opts.address_prefix));

    let grpc_url = ensure_grpc_scheme(&opts.rpcserver);
    let kaspad_client = GrpcClient::connect(grpc_url)
        .await
        .map_err(|e| DaemonError::Runtime(format!("failed to connect to kaspad '{}': {}", opts.rpcserver, e)))?;
    let kaspad: Arc<dyn super::kaspad::KaspadFacade> = Arc::new(GrpcKaspadFacade::new(Arc::new(kaspad_client)));

    let shutdown_notify = Arc::new(Notify::new());
    let sync_shutdown = Arc::new(Notify::new());
    let force_sync = Arc::new(Notify::new());

    let svc = KaspawalletdSvc::new(
        opts.version,
        shutdown_notify.clone(),
        state.clone(),
        kaspad.clone(),
        force_sync.clone(),
        opts.keysfile_path.clone(),
    );

    let sync_loop = SyncLoop::new(state, kaspad, sync_shutdown.clone(), force_sync);
    let sync_handle = tokio::spawn(async move { sync_loop.run().await });

    let serve_shutdown = combined_shutdown(shutdown_notify.clone());
    let serve_result = serve_inner(listener, svc, serve_shutdown).await;

    sync_shutdown.notify_one();
    if let Err(join_err) = sync_handle.await {
        return Err(DaemonError::Runtime(format!("sync task join error: {join_err}")));
    }
    serve_result
}

/// Test-facing entry. Used by integration tests to bind to an
/// ephemeral port. The caller passes the bound listener (typically
/// `TcpListener::bind("127.0.0.1:0")`), a pre-built service (with
/// or without shared state), and the explicit shutdown trigger so
/// the test can drive shutdown deterministically. Does NOT spawn
/// a sync loop or dial kaspad.
pub async fn serve_with_listener(listener: TcpListener, svc: KaspawalletdSvc, trigger: ShutdownTrigger) -> Result<(), DaemonError> {
    let notify = trigger.handle();
    let shutdown = async move { notify.notified().await };
    serve_inner(listener, svc, shutdown).await
}

async fn bind_listener(listen: &str) -> Result<TcpListener, DaemonError> {
    // `parse::<SocketAddr>` rejects `localhost` (it expects a
    // numeric host). Delegate to `tokio::net::TcpListener::bind`
    // when the operator-supplied string is non-numeric (it will
    // resolve DNS). Try a SocketAddr parse first because it
    // produces a clearer error message for malformed numeric
    // addresses (helpful in tests), and fall through to the
    // DNS-resolving bind on parse failure.
    let bound = match listen.parse::<SocketAddr>() {
        Ok(addr) => TcpListener::bind(addr).await,
        Err(_) => TcpListener::bind(listen).await,
    };
    bound.map_err(|source| DaemonError::Bind { addr: listen.to_owned(), source })
}

async fn serve_inner(
    listener: TcpListener,
    svc: KaspawalletdSvc,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<(), DaemonError> {
    let incoming = TcpListenerStream::new(listener);
    let server = KaspawalletdServer::new(svc).max_decoding_message_size(MAX_DAEMON_SEND_MSG_SIZE);
    Server::builder()
        .timeout(GRACEFUL_STOP_TIMEOUT)
        .add_service(server)
        .serve_with_incoming_shutdown(incoming, shutdown)
        .await
        .map_err(|e| DaemonError::Runtime(e.to_string()))
}

async fn combined_shutdown(notify: Arc<Notify>) {
    // SIGINT / SIGTERM (cross-platform via
    // `tokio::signal::ctrl_c`) OR an in-process `Shutdown` RPC --
    // whichever fires first ends the daemon. Composed via a
    // `tokio::select!`.
    tokio::select! {
        _ = tokio::signal::ctrl_c() => {},
        _ = notify.notified() => {},
    }
}

/// `kaspa_grpc_client::GrpcClient::connect` requires a `grpc://`
/// URL. The CLI's `--rpcserver` flag accepts both `host:port`
/// and `grpc://host:port`; bare-authority input is normalised by
/// prepending the `grpc://` scheme.
fn ensure_grpc_scheme(addr: &str) -> String {
    if addr.starts_with("grpc://") { addr.to_owned() } else { format!("grpc://{addr}") }
}

#[cfg(test)]
mod scheme_tests {
    use super::ensure_grpc_scheme;

    #[test]
    fn bare_authority_gets_grpc_scheme() {
        assert_eq!(ensure_grpc_scheme("localhost:16110"), "grpc://localhost:16110");
    }

    #[test]
    fn existing_grpc_scheme_preserved() {
        assert_eq!(ensure_grpc_scheme("grpc://node.example.org:16110"), "grpc://node.example.org:16110");
    }
}
