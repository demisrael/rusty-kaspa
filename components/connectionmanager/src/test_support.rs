//! Public test-support utilities for downstream integration tests.
//!
//! Compiled only under `feature = "test-utils"`. Production builds of
//! `kaspa-connectionmanager` do not link this module.
//!
//! The flagship export is [`FakeHostnameResolver`], a programmable
//! [`HostnameResolver`] implementation whose response table can be
//! mutated between resolution calls so tests can drive the dial-loop
//! and periodic-refresh paths through a deterministic, real-network-free
//! seam.

use crate::HostnameResolver;
use async_trait::async_trait;
use kaspa_utils::networking::PeerEndpointResolveError;
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
};

/// Programmable [`HostnameResolver`] for integration tests. Each entry
/// in the table maps a `(host, port)` key to either a fixed list of
/// resolved socket addresses or a string error reason. `set` and
/// `set_err` swap the response between calls so tests can simulate DNS
/// rotation and failure recovery.
///
/// Construct with [`FakeHostnameResolver::new`]; mutate via
/// [`set`](Self::set) and [`set_err`](Self::set_err); read invocation
/// counts via [`call_count`](Self::call_count).
#[derive(Debug, Default)]
pub struct FakeHostnameResolver {
    table: Mutex<HashMap<String, Result<Vec<SocketAddr>, String>>>,
    calls: AtomicU64,
}

impl FakeHostnameResolver {
    /// Construct an empty resolver. Every key returns `NotFound` until
    /// [`set`](Self::set) or [`set_err`](Self::set_err) is called.
    pub fn new() -> Self {
        Self::default()
    }

    /// Install a successful response: `host:port -> addrs`.
    pub fn set(&self, host: &str, port: u16, addrs: Vec<SocketAddr>) {
        self.table.lock().unwrap().insert(format!("{host}:{port}"), Ok(addrs));
    }

    /// Install an error response so resolution of `host:port` returns
    /// [`PeerEndpointResolveError::Lookup`] with the given reason.
    pub fn set_err(&self, host: &str, port: u16, reason: impl Into<String>) {
        self.table.lock().unwrap().insert(format!("{host}:{port}"), Err(reason.into()));
    }

    /// Total count of [`HostnameResolver::resolve`] invocations served
    /// since construction (or the last [`reset_call_count`](Self::reset_call_count)).
    pub fn call_count(&self) -> u64 {
        self.calls.load(Ordering::Relaxed)
    }

    /// Reset the invocation counter to zero.
    pub fn reset_call_count(&self) {
        self.calls.store(0, Ordering::Relaxed);
    }
}

#[async_trait]
impl HostnameResolver for FakeHostnameResolver {
    async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>, PeerEndpointResolveError> {
        self.calls.fetch_add(1, Ordering::Relaxed);
        let key = format!("{host}:{port}");
        let table = self.table.lock().unwrap();
        match table.get(&key) {
            Some(Ok(addrs)) => Ok(addrs.clone()),
            Some(Err(reason)) => {
                Err(PeerEndpointResolveError::Lookup { host: host.to_owned(), source: std::io::Error::other(reason.clone()) })
            }
            None => Err(PeerEndpointResolveError::Lookup {
                host: host.to_owned(),
                source: std::io::Error::new(std::io::ErrorKind::NotFound, format!("no fake entry for {key}")),
            }),
        }
    }
}
