//! `DaemonClient` -- dial helper around the tonic-generated
//! `KaspawalletdClient<Channel>`. Daemon-client subcommands
//! (`balance`, `send`, `new-address`, etc.) use this to construct
//! a connection from a `host:port` string without re-deriving the
//! tonic boilerplate per call-site.
//!
//! The dial path accepts both `host:port` (DNS-resolving) and
//! plain `ip:port` strings. For the integration tests the helper
//! also accepts an already-bound `SocketAddr` so tests do not need
//! to round-trip through a URI parse for a `127.0.0.1:<ephemeral>`
//! address.

use std::time::Duration;

use tonic::transport::{Channel, Endpoint};
use tonic::{Code, Status};

use super::error::DaemonError;
use super::pb::kaspawalletd_client::KaspawalletdClient;
use super::pb::{GetVersionRequest, GetVersionResponse, ShutdownRequest};

/// Default dial-connect timeout. Matches Go's per-RPC waitTimeout
/// at the connection level for the initial channel handshake; the
/// per-RPC waitTimeout itself remains a follow-on concern (the
/// client subcommands carry it through to `Request::set_timeout`
/// in the follow-on slice).
pub const DEFAULT_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);

/// High-level client wrapper. Owns the channel and exposes typed
/// methods per RPC; tests and CLI subcommands consume the typed
/// methods rather than reaching for the raw tonic client.
pub struct DaemonClient {
    inner: KaspawalletdClient<Channel>,
}

impl DaemonClient {
    /// Dial a daemon at the supplied `host:port` string. The
    /// connection is established eagerly so the caller observes
    /// `Connect` errors immediately rather than on the first RPC.
    pub async fn dial(addr: &str) -> Result<Self, DaemonError> {
        let uri = ensure_scheme(addr);
        let endpoint = Endpoint::from_shared(uri)
            .map_err(|e| DaemonError::Runtime(format!("invalid daemon endpoint '{addr}': {e}")))?
            .connect_timeout(DEFAULT_CONNECT_TIMEOUT);
        let channel = endpoint.connect().await.map_err(|e| DaemonError::Runtime(format!("dial '{addr}': {e}")))?;
        Ok(Self { inner: KaspawalletdClient::new(channel) })
    }

    /// Invoke the `GetVersion` RPC and return the daemon's version
    /// string. Errors propagate the raw `tonic::Status`.
    pub async fn get_version(&mut self) -> Result<String, Status> {
        let resp: GetVersionResponse = self.inner.get_version(GetVersionRequest {}).await?.into_inner();
        Ok(resp.version)
    }

    /// Invoke the `Shutdown` RPC. The daemon honours the request
    /// and exits within the graceful-stop window. Treat
    /// `Code::Cancelled` and `Code::Unavailable` as benign since
    /// they signal that the daemon's graceful-stop closed the
    /// connection before the response was flushed.
    pub async fn shutdown(&mut self) -> Result<(), Status> {
        match self.inner.shutdown(ShutdownRequest {}).await {
            Ok(_resp) => Ok(()),
            Err(status) if matches!(status.code(), Code::Cancelled | Code::Unavailable) => Ok(()),
            Err(status) => Err(status),
        }
    }

    /// Consume the wrapper and return the underlying generated
    /// client. Useful for follow-on slices that want direct access
    /// to RPCs the wrapper does not yet name.
    pub fn into_inner(self) -> KaspawalletdClient<Channel> {
        self.inner
    }

    /// Borrow the underlying generated client.
    pub fn inner_mut(&mut self) -> &mut KaspawalletdClient<Channel> {
        &mut self.inner
    }
}

/// `Endpoint::from_shared` requires a URI; the daemon's
/// `--daemonaddress` flag holds an authority-only `host:port` for
/// Go-CLI compatibility. This helper inserts the `http://` scheme
/// when the input lacks one. gRPC over TLS is out of scope here
/// (Go's daemon is plaintext) and a follow-on slice can extend the
/// dialer to accept `https://` URIs explicitly.
fn ensure_scheme(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") { addr.to_owned() } else { format!("http://{addr}") }
}

#[cfg(test)]
mod scheme_tests {
    use super::ensure_scheme;

    #[test]
    fn host_port_gets_http_scheme() {
        assert_eq!(ensure_scheme("localhost:8082"), "http://localhost:8082");
    }

    #[test]
    fn ipv4_port_gets_http_scheme() {
        assert_eq!(ensure_scheme("127.0.0.1:8082"), "http://127.0.0.1:8082");
    }

    #[test]
    fn existing_http_scheme_preserved() {
        assert_eq!(ensure_scheme("http://localhost:8082"), "http://localhost:8082");
    }

    #[test]
    fn existing_https_scheme_preserved() {
        assert_eq!(ensure_scheme("https://node.example.org:443"), "https://node.example.org:443");
    }
}
