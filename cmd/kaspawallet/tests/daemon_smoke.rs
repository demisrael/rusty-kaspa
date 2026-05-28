//! Integration smoke test for the `kaspawallet` daemon mode.
//!
//! The test spawns the daemon in-process on an ephemeral
//! `127.0.0.1` TCP port, dials it with the in-crate `DaemonClient`
//! helper, exercises the lightweight RPCs that do not depend on
//! the (still-to-land) kaspad sync subsystem, and asserts that
//! the daemon shuts down cleanly on receipt of the `Shutdown` RPC.
//!
//! What this proves at the cargo-test layer:
//!
//! - Listener binds on a caller-supplied `TcpListener` (no fixed
//!   port; safe for parallel test execution).
//! - tonic server wiring routes RPCs through the
//!   `KaspawalletdSvc` implementation.
//! - `DaemonClient::dial` accepts an `ip:port` authority and
//!   establishes a working channel.
//! - `GetVersion` round-trips, returning the configured version
//!   string.
//! - RPCs that depend on the kaspad sync subsystem return
//!   `Code::FailedPrecondition` over the wire (the daemon is
//!   running without a shared state in this test; production
//!   handlers also return FailedPrecondition when the sync loop
//!   has not yet reached `first_sync_done`).
//! - `Shutdown` terminates the daemon and the server task exits
//!   cleanly.

use std::time::Duration;

use tokio::net::TcpListener;
use tonic::Code;

use kaspawallet::daemon::pb::ShowAddressesRequest;
use kaspawallet::daemon::{DaemonClient, KaspawalletdSvc, ShutdownTrigger, serve_with_listener};

const TEST_VERSION: &str = "daemon-smoke-1.0.0";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn daemon_serves_get_version_and_shuts_down_cleanly() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");
    let addr = listener.local_addr().expect("local_addr");

    let (trigger, notify) = ShutdownTrigger::new();
    let svc = KaspawalletdSvc::without_state(TEST_VERSION, notify);

    let server_task = tokio::spawn(async move { serve_with_listener(listener, svc, trigger).await });

    // Give the server's `serve_with_incoming_shutdown` a chance to
    // poll its shutdown future before we dial. The yield is enough
    // because the server task is already runnable and the listener
    // socket is bound; the connect that follows then drives the
    // server through the gRPC handshake.
    tokio::task::yield_now().await;

    let endpoint = format!("{addr}");
    let mut client = DaemonClient::dial(&endpoint).await.expect("dial daemon");

    let version = client.get_version().await.expect("get_version round-trip");
    assert_eq!(version, TEST_VERSION);

    // View RPC without shared state: assert the daemon returns
    // `Code::FailedPrecondition` on the wire (this test wires a
    // service without state, so the production "not synced yet"
    // path is what surfaces).
    let show_status =
        client.inner_mut().show_addresses(ShowAddressesRequest {}).await.expect_err("expected FailedPrecondition on the wire");
    assert_eq!(show_status.code(), Code::FailedPrecondition);

    client.shutdown().await.expect("shutdown RPC succeeds");

    // The daemon must terminate within the graceful-stop window.
    // We allow a generous slack on top of `GRACEFUL_STOP_TIMEOUT`
    // to account for runtime scheduling and tonic's
    // graceful-shutdown handshake.
    let join_result = tokio::time::timeout(Duration::from_secs(5), server_task)
        .await
        .expect("daemon did not terminate within the graceful-stop window");
    let serve_result = join_result.expect("server task panicked");
    serve_result.expect("daemon serve loop returned an error");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn external_trigger_fire_terminates_daemon() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind ephemeral port");

    let (trigger, notify) = ShutdownTrigger::new();
    let svc = KaspawalletdSvc::without_state(TEST_VERSION, notify);

    // Fire shutdown BEFORE entering serve. `notify_one`'s permit
    // semantics guarantee the server-side shutdown future sees the
    // signal on its first poll; the daemon must terminate cleanly
    // without ever accepting an RPC.
    trigger.fire();

    let serve_result = serve_with_listener(listener, svc, trigger).await;
    serve_result.expect("daemon serve loop returned an error on pre-fired shutdown");
}
