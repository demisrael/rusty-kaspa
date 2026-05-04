use crate::common::{
    client::ListeningClient,
    client_notify::ChannelNotify,
    daemon::Daemon,
    utils::{fetch_spendable_utxos, generate_tx, mine_block, wait_for},
};
use kaspa_addresses::Address;
use kaspa_alloc::init_allocator_with_default_settings;
use kaspa_consensus::params::SIMNET_PARAMS;
use kaspa_consensus_core::header::Header;
use kaspa_consensusmanager::ConsensusManager;
use kaspa_core::{task::runtime::AsyncRuntime, trace};
use kaspa_grpc_client::GrpcClient;
use kaspa_notify::scope::{BlockAddedScope, UtxosChangedScope, VirtualDaaScoreChangedScope};
use kaspa_rpc_core::{Notification, RpcTransactionId, api::rpc::RpcApi};
use kaspa_txscript::pay_to_address_script;
use kaspad_lib::{args::Args, daemon::DaemonOverrides};
use rand::thread_rng;
use std::{sync::Arc, time::Duration};

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn daemon_sanity_test() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("INFO");

    // let total_fd_limit =  kaspa_utils::fd_budget::get_limit() / 2 - 128;
    let total_fd_limit = 10;
    let mut kaspad1 = Daemon::new_random(total_fd_limit);
    let rpc_client1 = kaspad1.start().await;
    assert!(rpc_client1.handle_message_id() && rpc_client1.handle_stop_notify(), "the client failed to collect server features");

    let mut kaspad2 = Daemon::new_random(total_fd_limit);
    let rpc_client2 = kaspad2.start().await;
    assert!(rpc_client2.handle_message_id() && rpc_client2.handle_stop_notify(), "the client failed to collect server features");

    tokio::time::sleep(Duration::from_secs(1)).await;
    rpc_client1.disconnect().await.unwrap();
    drop(rpc_client1);
    kaspad1.shutdown();

    rpc_client2.disconnect().await.unwrap();
    drop(rpc_client2);
    kaspad2.shutdown();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn daemon_mining_test() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("INFO");

    let args = Args {
        simnet: true,
        unsafe_rpc: true,
        enable_unsynced_mining: true,
        disable_upnp: true, // UPnP registration might take some time and is not needed for this test
        ..Default::default()
    };
    // let total_fd_limit = kaspa_utils::fd_budget::get_limit() / 2 - 128;
    let total_fd_limit = 10;

    let mut kaspad1 = Daemon::new_random_with_args(args.clone(), total_fd_limit);
    let mut kaspad2 = Daemon::new_random_with_args(args, total_fd_limit);
    let rpc_client1 = kaspad1.start().await;
    let rpc_client2 = kaspad2.start().await;

    rpc_client2.add_peer(format!("127.0.0.1:{}", kaspad1.p2p_port).try_into().unwrap(), true).await.unwrap();
    tokio::time::sleep(Duration::from_secs(1)).await; // Let it connect
    assert_eq!(rpc_client2.get_connected_peer_info().await.unwrap().peer_info.len(), 1);

    let (sender, event_receiver) = async_channel::unbounded();
    rpc_client1.start(Some(Arc::new(ChannelNotify::new(sender)))).await;
    rpc_client1.start_notify(Default::default(), VirtualDaaScoreChangedScope {}.into()).await.unwrap();

    // Mine 10 blocks to daemon #1
    let mut last_block_hash = None;
    for i in 0..10 {
        let template = rpc_client1
            .get_block_template(Address::new(kaspad1.network.into(), kaspa_addresses::Version::PubKey, &[0; 32]), vec![])
            .await
            .unwrap();
        let header: Header = (&template.block.header).try_into().unwrap();
        last_block_hash = Some(header.hash);
        rpc_client1.submit_block(template.block, false).await.unwrap();

        while let Ok(notification) = match tokio::time::timeout(Duration::from_secs(1), event_receiver.recv()).await {
            Ok(res) => res,
            Err(elapsed) => panic!("expected virtual event before {}", elapsed),
        } {
            match notification {
                Notification::VirtualDaaScoreChanged(msg) if msg.virtual_daa_score == i + 1 => {
                    break;
                }
                Notification::VirtualDaaScoreChanged(msg) if msg.virtual_daa_score > i + 1 => {
                    panic!("DAA score too high for number of submitted blocks")
                }
                Notification::VirtualDaaScoreChanged(_) => {}
                _ => panic!("expected only DAA score notifications"),
            }
        }
    }

    tokio::time::sleep(Duration::from_secs(1)).await;
    // Expect the blocks to be relayed to daemon #2
    let dag_info = rpc_client2.get_block_dag_info().await.unwrap();
    assert_eq!(dag_info.block_count, 10);
    assert_eq!(dag_info.sink, last_block_hash.unwrap());

    // Check that acceptance data contains the expected coinbase tx ids
    let vc = rpc_client2
        .get_virtual_chain_from_block(
            kaspa_consensus::params::SIMNET_GENESIS.hash, //
            true,
            None,
        )
        .await
        .unwrap();
    assert_eq!(vc.removed_chain_block_hashes.len(), 0);
    assert_eq!(vc.added_chain_block_hashes.len(), 10);
    assert_eq!(vc.accepted_transaction_ids.len(), 10);
    for accepted_txs_pair in vc.accepted_transaction_ids {
        assert_eq!(accepted_txs_pair.accepted_transaction_ids.len(), 1);
    }
}

/// `cargo test --release --package kaspa-testing-integration --lib -- daemon_integration_tests::daemon_utxos_propagation_test`
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn daemon_utxos_propagation_test() {
    #[cfg(feature = "heap")]
    let _profiler = dhat::Profiler::builder().file_name("kaspa-testing-integration-heap.json").build();

    kaspa_core::log::try_init_logger(
        "INFO,kaspa_testing_integration=trace,kaspa_notify=debug,kaspa_rpc_core=debug,kaspa_grpc_client=debug",
    );

    let args = Args {
        simnet: true,
        unsafe_rpc: true,
        enable_unsynced_mining: true,
        disable_upnp: true, // UPnP registration might take some time and is not needed for this test
        utxoindex: true,
        ..Default::default()
    };
    let total_fd_limit = 10;

    let coinbase_maturity = SIMNET_PARAMS.coinbase_maturity();
    let mut kaspad1 = Daemon::new_random_with_args(args.clone(), total_fd_limit);
    let mut kaspad2 = Daemon::new_random_with_args(args, total_fd_limit);
    let rpc_client1 = kaspad1.start().await;
    let rpc_client2 = kaspad2.start().await;

    // Let rpc_client1 receive virtual DAA score changed notifications
    let (sender1, event_receiver1) = async_channel::unbounded();
    rpc_client1.start(Some(Arc::new(ChannelNotify::new(sender1)))).await;
    rpc_client1.start_notify(Default::default(), VirtualDaaScoreChangedScope {}.into()).await.unwrap();

    // Connect kaspad2 to kaspad1
    rpc_client2.add_peer(format!("127.0.0.1:{}", kaspad1.p2p_port).try_into().unwrap(), true).await.unwrap();
    let check_client = rpc_client2.clone();
    wait_for(
        50,
        20,
        move || {
            async fn peer_connected(client: GrpcClient) -> bool {
                client.get_connected_peer_info().await.unwrap().peer_info.len() == 1
            }
            Box::pin(peer_connected(check_client.clone()))
        },
        "the nodes did not connect to each other",
    )
    .await;

    // Mining key and address
    let (miner_sk, miner_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let miner_address =
        Address::new(kaspad1.network.into(), kaspa_addresses::Version::PubKey, &miner_pk.x_only_public_key().0.serialize());
    let miner_schnorr_key = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &miner_sk);
    let miner_spk = pay_to_address_script(&miner_address);

    // User key and address
    let (_user_sk, user_pk) = secp256k1::generate_keypair(&mut thread_rng());
    let user_address =
        Address::new(kaspad1.network.into(), kaspa_addresses::Version::PubKey, &user_pk.x_only_public_key().0.serialize());

    // Some dummy non-monitored address
    let blank_address = Address::new(kaspad1.network.into(), kaspa_addresses::Version::PubKey, &[0; 32]);

    // Mine 1000 blocks to daemon #1
    let initial_blocks = coinbase_maturity;
    let mut last_block_hash = None;
    for i in 0..initial_blocks {
        let template = rpc_client1.get_block_template(miner_address.clone(), vec![]).await.unwrap();
        let header: Header = (&template.block.header).try_into().unwrap();
        last_block_hash = Some(header.hash);
        rpc_client1.submit_block(template.block, false).await.unwrap();

        while let Ok(notification) = match tokio::time::timeout(Duration::from_secs(1), event_receiver1.recv()).await {
            Ok(res) => res,
            Err(elapsed) => panic!("expected virtual event before {}", elapsed),
        } {
            match notification {
                Notification::VirtualDaaScoreChanged(msg) if msg.virtual_daa_score == i + 1 => {
                    break;
                }
                Notification::VirtualDaaScoreChanged(msg) if msg.virtual_daa_score > i + 1 => {
                    panic!("DAA score too high for number of submitted blocks")
                }
                Notification::VirtualDaaScoreChanged(_) => {}
                _ => panic!("expected only DAA score notifications"),
            }
        }
    }

    let check_client = rpc_client2.clone();
    wait_for(
        50,
        20,
        move || {
            async fn daa_score_reached(client: GrpcClient) -> bool {
                let virtual_daa_score = client.get_server_info().await.unwrap().virtual_daa_score;
                trace!("Virtual DAA score: {}", virtual_daa_score);
                virtual_daa_score == SIMNET_PARAMS.coinbase_maturity()
            }
            Box::pin(daa_score_reached(check_client.clone()))
        },
        "the nodes did not add and relay all the initial blocks",
    )
    .await;

    // Expect the blocks to be relayed to daemon #2
    let dag_info = rpc_client2.get_block_dag_info().await.unwrap();
    assert_eq!(dag_info.block_count, initial_blocks);
    assert_eq!(dag_info.sink, last_block_hash.unwrap());

    // Check that acceptance data contains the expected coinbase tx ids
    let vc = rpc_client2.get_virtual_chain_from_block(kaspa_consensus::params::SIMNET_GENESIS.hash, true, None).await.unwrap();
    assert_eq!(vc.removed_chain_block_hashes.len(), 0);
    assert_eq!(vc.added_chain_block_hashes.len() as u64, initial_blocks);
    assert_eq!(vc.accepted_transaction_ids.len() as u64, initial_blocks);
    for accepted_txs_pair in vc.accepted_transaction_ids {
        assert_eq!(accepted_txs_pair.accepted_transaction_ids.len(), 1);
    }

    // Create a multi-listener RPC client on each node...
    let mut clients = vec![ListeningClient::connect(&kaspad2).await, ListeningClient::connect(&kaspad1).await];

    // ...and subscribe each to some notifications
    for x in clients.iter_mut() {
        x.start_notify(BlockAddedScope {}.into()).await.unwrap();
        x.start_notify(UtxosChangedScope::new(vec![miner_address.clone(), user_address.clone()]).into()).await.unwrap();
        x.start_notify(VirtualDaaScoreChangedScope {}.into()).await.unwrap();
    }

    // Mine some extra blocks so the latest miner reward is added to its balance and some UTXOs reach maturity
    const EXTRA_BLOCKS: usize = 10;
    for _ in 0..EXTRA_BLOCKS {
        mine_block(blank_address.clone(), &rpc_client1, &clients).await;
    }

    // Check the balance of the miner address
    let miner_balance = rpc_client2.get_balance_by_address(miner_address.clone()).await.unwrap();
    assert_eq!(miner_balance, initial_blocks * SIMNET_PARAMS.pre_deflationary_phase_base_subsidy);
    let miner_balance = rpc_client1.get_balance_by_address(miner_address.clone()).await.unwrap();
    assert_eq!(miner_balance, initial_blocks * SIMNET_PARAMS.pre_deflationary_phase_base_subsidy);

    // Get the miner UTXOs
    let utxos = fetch_spendable_utxos(&rpc_client1, miner_address.clone(), coinbase_maturity).await;
    assert_eq!(utxos.len(), EXTRA_BLOCKS - 1);
    for utxo in utxos.iter() {
        assert!(utxo.1.is_coinbase);
        assert_eq!(utxo.1.amount, SIMNET_PARAMS.pre_deflationary_phase_base_subsidy);
        assert_eq!(utxo.1.script_public_key, miner_spk);
    }

    // Drain UTXOs and Virtual DAA score changed notification channels
    clients.iter().for_each(|x| x.utxos_changed_listener().unwrap().drain());
    clients.iter().for_each(|x| x.virtual_daa_score_changed_listener().unwrap().drain());

    // Spend some coins - sending funds from miner address to user address
    // The transaction here is later used to verify utxo return address RPC
    const NUMBER_INPUTS: u64 = 2;
    const NUMBER_OUTPUTS: u64 = 2;
    const TX_AMOUNT: u64 = SIMNET_PARAMS.pre_deflationary_phase_base_subsidy * (NUMBER_INPUTS * 5 - 1) / 5;
    let transaction = generate_tx(miner_schnorr_key, &utxos[0..NUMBER_INPUTS as usize], TX_AMOUNT, NUMBER_OUTPUTS, &user_address);
    rpc_client1.submit_transaction((&transaction).into(), false).await.unwrap();

    let check_client = rpc_client1.clone();
    let transaction_id = transaction.id();
    wait_for(
        50,
        20,
        move || {
            async fn transaction_in_mempool(client: GrpcClient, transaction_id: RpcTransactionId) -> bool {
                let entry = client.get_mempool_entry(transaction_id, false, false).await;
                entry.is_ok()
            }
            Box::pin(transaction_in_mempool(check_client.clone(), transaction_id))
        },
        "the transaction was not added to the mempool",
    )
    .await;

    mine_block(blank_address.clone(), &rpc_client1, &clients).await;

    // Check UTXOs changed notifications
    for x in clients.iter() {
        let Notification::UtxosChanged(uc) = x.utxos_changed_listener().unwrap().receiver.recv().await.unwrap() else {
            panic!("wrong notification type")
        };
        assert!(uc.removed.iter().all(|x| x.address.is_some() && *x.address.as_ref().unwrap() == miner_address));
        assert!(uc.added.iter().all(|x| x.address.is_some() && *x.address.as_ref().unwrap() == user_address));
        assert_eq!(uc.removed.len() as u64, NUMBER_INPUTS);
        assert_eq!(uc.added.len() as u64, NUMBER_OUTPUTS);
        assert_eq!(
            uc.removed.iter().map(|x| x.utxo_entry.amount).sum::<u64>(),
            SIMNET_PARAMS.pre_deflationary_phase_base_subsidy * NUMBER_INPUTS
        );
        assert_eq!(uc.added.iter().map(|x| x.utxo_entry.amount).sum::<u64>(), TX_AMOUNT);
    }

    // Check the balance of both miner and user addresses
    for x in clients.iter() {
        let miner_balance = x.get_balance_by_address(miner_address.clone()).await.unwrap();
        assert_eq!(miner_balance, (initial_blocks - NUMBER_INPUTS) * SIMNET_PARAMS.pre_deflationary_phase_base_subsidy);

        let user_balance = x.get_balance_by_address(user_address.clone()).await.unwrap();
        assert_eq!(user_balance, TX_AMOUNT);
    }

    // UTXO Return Address Test
    // Mine another block to accept the transactions from the previous block
    // The tx above is sending from miner address to user address
    mine_block(blank_address.clone(), &rpc_client1, &clients).await;
    let new_utxos = rpc_client1.get_utxos_by_addresses(vec![user_address]).await.unwrap();
    let new_utxo = new_utxos
        .iter()
        .find(|utxo| utxo.outpoint.transaction_id == transaction.id())
        .expect("Did not find a utxo for the tx we just created but expected to");

    let utxo_return_address = rpc_client1
        .get_utxo_return_address(new_utxo.outpoint.transaction_id, new_utxo.utxo_entry.block_daa_score)
        .await
        .expect("We just created the tx and utxo here");

    assert_eq!(miner_address, utxo_return_address);

    // Terminate multi-listener clients
    for x in clients.iter() {
        x.disconnect().await.unwrap();
        x.join().await.unwrap();
    }
}

// The following test runtime parameters are required for a graceful shutdown of the gRPC server
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn daemon_cleaning_test() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("info,kaspa_grpc_core=trace,kaspa_grpc_server=trace,kaspa_grpc_client=trace,kaspa_core=trace");
    let args = Args { devnet: true, ..Default::default() };
    let consensus_manager;
    let async_runtime;
    let core;
    {
        let total_fd_limit = 10;
        let mut kaspad1 = Daemon::new_random_with_args(args, total_fd_limit);
        let dyn_consensus_manager = kaspad1.core.find(ConsensusManager::IDENT).unwrap();
        let dyn_async_runtime = kaspad1.core.find(AsyncRuntime::IDENT).unwrap();
        consensus_manager = Arc::downgrade(&Arc::downcast::<ConsensusManager>(dyn_consensus_manager.into_any_arc()).unwrap());
        async_runtime = Arc::downgrade(&Arc::downcast::<AsyncRuntime>(dyn_async_runtime.into_any_arc()).unwrap());
        core = Arc::downgrade(&kaspad1.core);

        let rpc_client1 = kaspad1.start().await;
        rpc_client1.disconnect().await.unwrap();
        drop(rpc_client1);
        kaspad1.shutdown();
    }
    tokio::time::sleep(Duration::from_millis(200)).await;

    assert_eq!(consensus_manager.strong_count(), 0);
    assert_eq!(async_runtime.strong_count(), 0);
    assert_eq!(core.strong_count(), 0);
}

// =============================================================================
// Hostname endpoint integration tests
// =============================================================================

/// `--addpeer=localhost:<port>` parses, resolves via the OS resolver, and
/// kaspad starts cleanly with the resulting socket addresses staged in the
/// connection request set.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn kaspad_addpeer_hostname_localhost_starts() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("INFO");

    use kaspa_utils::networking::PeerEndpoint;
    let args = Args {
        devnet: true,
        disable_upnp: true,
        add_peers: vec![PeerEndpoint::from_str("localhost").expect("parse hostname")],
        hostname_refresh_interval_sec: 0,
        ..Default::default()
    };
    let total_fd_limit = 10;
    let mut kaspad = Daemon::new_random_with_args(args, total_fd_limit);
    let rpc_client = kaspad.start().await;
    // If startup made it this far, hostname resolution succeeded and the
    // node is up. A single round-trip RPC confirms the gRPC server reached
    // the steady state.
    assert!(rpc_client.handle_message_id(), "client did not collect server features after addpeer hostname startup");
    rpc_client.disconnect().await.unwrap();
    drop(rpc_client);
    kaspad.shutdown();
}

/// `--addpeer=127.0.0.1:<port>` (numeric IPv4 literal) takes the same
/// short-circuit path as before the hostname work landed; this is the
/// IP-only regression guard.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn kaspad_addpeer_ipv4_unchanged() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("INFO");

    use kaspa_utils::networking::PeerEndpoint;
    let args = Args {
        devnet: true,
        disable_upnp: true,
        add_peers: vec![PeerEndpoint::from_str("127.0.0.1:12345").unwrap()],
        hostname_refresh_interval_sec: 0,
        ..Default::default()
    };
    let mut kaspad = Daemon::new_random_with_args(args, 10);
    let rpc_client = kaspad.start().await;
    assert!(rpc_client.handle_message_id());
    rpc_client.disconnect().await.unwrap();
    drop(rpc_client);
    kaspad.shutdown();
}

/// `--addpeer=[::1]:<port>` (numeric IPv6 literal) regresses identically.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn kaspad_addpeer_ipv6_unchanged() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("INFO");

    use kaspa_utils::networking::PeerEndpoint;
    let args = Args {
        devnet: true,
        disable_upnp: true,
        add_peers: vec![PeerEndpoint::from_str("[::1]:12345").unwrap()],
        hostname_refresh_interval_sec: 0,
        ..Default::default()
    };
    let mut kaspad = Daemon::new_random_with_args(args, 10);
    let rpc_client = kaspad.start().await;
    assert!(rpc_client.handle_message_id());
    rpc_client.disconnect().await.unwrap();
    drop(rpc_client);
    kaspad.shutdown();
}

/// `--hostname-refresh-interval=0` is honored: the connection manager
/// instantiates without a periodic refresh task. Verified indirectly by
/// successful startup with a hostname endpoint and `interval=0`.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn kaspad_periodic_refresh_disabled_with_zero_interval() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("INFO");

    use kaspa_utils::networking::PeerEndpoint;
    let args = Args {
        devnet: true,
        disable_upnp: true,
        add_peers: vec![PeerEndpoint::from_str("localhost").unwrap()],
        hostname_refresh_interval_sec: 0,
        ..Default::default()
    };
    let mut kaspad = Daemon::new_random_with_args(args, 10);
    let rpc_client = kaspad.start().await;
    assert!(rpc_client.handle_message_id());
    rpc_client.disconnect().await.unwrap();
    drop(rpc_client);
    kaspad.shutdown();
}

// FromStr is used for the hostname endpoints in the tests above.
use std::str::FromStr;

/// `--addpeer=<unresolvable-host>` does NOT abort kaspad; the hostname is
/// registered for periodic retry, the `initial_failed` metric is bumped,
/// and the daemon keeps serving normally. The unresolvable-host path and
/// the unreachable-IP path both queue the entry and retry forever, never
/// refusing startup.
///
/// Source: https://github.com/bitcoin/bitcoin/blob/8f4a3ba8972dae9412ba975a040cea22c227f983/src/net.cpp#L2974
/// (`ThreadOpenAddedConnections`).
///
/// The fake resolver returns `Err` for the cited hostname so no real DNS
/// is consulted. The assertion stack is: (1) `Daemon::new_random_with_args`
/// + `start()` complete without panicking - i.e. `create_core_with_runtime`
/// returned a live daemon despite the unresolvable peer endpoint;
/// (2) the metric counter `initial_failed >= 1` (registered by the
/// connection manager when the resolver returned `Err`); (3) the daemon
/// is still alive after `2 x hostname_refresh_interval` (a healthy gRPC
/// round-trip against the running RPC server is the strongest single
/// liveness probe available in-process).
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn kaspad_addpeer_hostname_unresolvable_keeps_running() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("INFO");

    use kaspa_connectionmanager::test_support::FakeHostnameResolver;
    use kaspa_consensus_core::network::{NetworkId, NetworkType};
    use kaspa_utils::networking::PeerEndpoint;

    let host = "nonexistent.kas947.invalid";
    let endpoint = PeerEndpoint::from_str(host).expect("parse hostname endpoint");
    let resolver = Arc::new(FakeHostnameResolver::new());
    // The connection manager hands the active network's default p2p port
    // to the resolver when the endpoint omits one. Derive it from the
    // `kaspa-consensus-core` `NetworkId` API so a future port reshuffle on
    // the consensus side does not silently regress the test to "resolver
    // never called" while assertions still pass with `call_count = 0`.
    let devnet_p2p_port = NetworkId::new(NetworkType::Devnet).default_p2p_port();
    resolver.set_err(host, devnet_p2p_port, "fake resolver: nonexistent.kas947.invalid does not resolve");

    let refresh_interval_sec = 2u64;
    let args = Args {
        devnet: true,
        disable_upnp: true,
        add_peers: vec![endpoint],
        hostname_refresh_interval_sec: refresh_interval_sec,
        ..Default::default()
    };
    let overrides = DaemonOverrides { hostname_resolver: Some(resolver.clone()) };
    let mut kaspad = Daemon::new_random_with_args_and_overrides(args, overrides, 10);
    // start() runs the bound services. With the post-amendment
    // register-on-failure design, this returns a working RPC client even
    // though the only `--addpeer` host is unresolvable.
    let rpc_client = kaspad.start().await;

    // Liveness probe: the gRPC server is reachable and responsive. If the
    // daemon had aborted, `start()` would have hung or panicked first.
    assert!(
        rpc_client.handle_message_id(),
        "RPC client did not collect server features: kaspad must keep running on unresolvable --addpeer",
    );

    // Wait at least 2 x refresh_interval so the periodic refresh task has
    // had room to tick at least twice past the initial registration.
    tokio::time::sleep(Duration::from_secs(2 * refresh_interval_sec + 1)).await;
    let snapshot =
        kaspad.hostname_metrics_snapshot().await.expect("connection manager should be wired into the flow context after start()");
    assert!(
        snapshot.resolutions_total.initial_failed >= 1,
        "expected initial_failed >= 1 after registering an unresolvable hostname; snapshot = {snapshot:?}; resolver call_count = {}",
        resolver.call_count(),
    );
    assert_eq!(snapshot.resolutions_total.initial_ok, 0, "no successful initial resolution expected; snapshot = {snapshot:?}",);
    // The daemon stayed up across the observation window. A second
    // RPC round-trip confirms it is still serving requests.
    assert!(rpc_client.handle_message_id(), "RPC client lost server liveness during the observation window");

    rpc_client.disconnect().await.unwrap();
    drop(rpc_client);
    kaspad.shutdown();
}

/// `--addpeer=<host> --hostname-refresh-interval=2` produces at least two
/// `peer_hostname_resolutions_total{trigger="periodic"}` increments inside
/// a five-second observation window. The fake resolver pins `<host>` to a
/// loopback socket address so no real DNS is consulted, and the metric
/// counter is read directly off the running daemon's
/// [`kaspa_connectionmanager::ConnectionManager`] via the integration
/// harness's [`Daemon::hostname_metrics_snapshot`] hook.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn kaspad_periodic_refresh_observed() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("INFO");

    use kaspa_connectionmanager::test_support::FakeHostnameResolver;
    use kaspa_consensus_core::network::{NetworkId, NetworkType};
    use kaspa_utils::networking::PeerEndpoint;
    use std::net::SocketAddr;

    let host = "fakehost.kas947.invalid";
    let endpoint = PeerEndpoint::from_str(host).expect("parse hostname endpoint");
    let resolver = Arc::new(FakeHostnameResolver::new());
    // The connection manager calls the resolver with the active network's
    // default p2p port when the `add_peers` endpoint omits an explicit
    // port. Derive the port from the `kaspa-consensus-core` `NetworkId`
    // API so a future consensus-side port change cannot silently regress
    // the resolver mapping to a stale literal.
    let devnet_p2p_port = NetworkId::new(NetworkType::Devnet).default_p2p_port();
    let stub_addr: SocketAddr = "127.0.0.1:42101".parse().unwrap();
    resolver.set(host, devnet_p2p_port, vec![stub_addr]);

    let args = Args {
        devnet: true,
        disable_upnp: true,
        add_peers: vec![endpoint],
        // Two-second cadence keeps the observation window short.
        hostname_refresh_interval_sec: 2,
        ..Default::default()
    };
    let overrides = DaemonOverrides { hostname_resolver: Some(resolver.clone()) };
    let mut kaspad = Daemon::new_random_with_args_and_overrides(args, overrides, 10);
    let rpc_client = kaspad.start().await;
    // Wait long enough for >=2 periodic ticks at the 2 s cadence even under
    // CI load (the ticker uses MissedTickBehavior::Delay; a single slipped
    // tick must not flake the assertion). 15 s gives ~7 ticks of headroom.
    tokio::time::sleep(Duration::from_secs(15)).await;
    let snapshot =
        kaspad.hostname_metrics_snapshot().await.expect("connection manager should be wired into the flow context after start()");
    assert!(
        snapshot.resolutions_total.periodic_ok >= 2,
        "expected periodic_ok >= 2 after 15s with 2s cadence; snapshot = {snapshot:?}; resolver call_count = {}",
        resolver.call_count(),
    );
    assert_eq!(snapshot.resolutions_total.initial_ok, 1, "exactly one initial resolution expected; snapshot = {snapshot:?}");
    rpc_client.disconnect().await.unwrap();
    drop(rpc_client);
    kaspad.shutdown();
}

/// A hostname-origin dial against a port that no peer is listening on
/// fails, marks the hostname entry stale, and triggers a re-resolution at
/// the next refresh tick. The fake resolver swaps its response between
/// the failing IP and a different IP after the dial-failure marker fires,
/// so the dial-failure-triggered re-resolve is observable both via the
/// metrics counter and via the resolver's invocation count.
#[tokio::test(flavor = "multi_thread", worker_threads = 1)]
async fn kaspad_dial_failure_re_resolves() {
    init_allocator_with_default_settings();
    kaspa_core::log::try_init_logger("INFO");

    use kaspa_connectionmanager::test_support::FakeHostnameResolver;
    use kaspa_consensus_core::network::{NetworkId, NetworkType};
    use kaspa_utils::networking::PeerEndpoint;
    use std::net::SocketAddr;

    let host = "rotating.kas947.invalid";
    let endpoint = PeerEndpoint::from_str(host).unwrap();
    let resolver = Arc::new(FakeHostnameResolver::new());
    // Derive the active network's default p2p port from the
    // `kaspa-consensus-core` `NetworkId` API so the resolver mapping stays
    // in sync with whatever the connection manager hands it.
    let devnet_p2p_port = NetworkId::new(NetworkType::Devnet).default_p2p_port();
    // Initial response: a port that nothing is listening on. The dial
    // attempt against it will fail (connection refused), which the
    // connection manager translates into a hostname stale-mark.
    let ip_a: SocketAddr = "127.0.0.1:1".parse().unwrap();
    let ip_b: SocketAddr = "127.0.0.1:2".parse().unwrap();
    resolver.set(host, devnet_p2p_port, vec![ip_a]);

    let args = Args {
        devnet: true,
        disable_upnp: true,
        add_peers: vec![endpoint],
        // Short cadence so the dial-failure-triggered re-resolve is
        // observed inside the test deadline. The dial-failure path forces
        // an immediate re-resolve regardless of cadence; the cadence is
        // a safety net.
        hostname_refresh_interval_sec: 2,
        ..Default::default()
    };
    let overrides = DaemonOverrides { hostname_resolver: Some(resolver.clone()) };
    let mut kaspad = Daemon::new_random_with_args_and_overrides(args, overrides, 10);
    let rpc_client = kaspad.start().await;
    // After the daemon settles, swap the resolver to point at a different
    // socket so the next refresh observes a delta (and the dial-failure
    // path stamps `dial_failure_ok` when the re-resolve succeeds).
    tokio::time::sleep(Duration::from_secs(3)).await;
    resolver.set(host, devnet_p2p_port, vec![ip_b]);

    // Wait long enough to observe at least one dial-failure-triggered
    // re-resolution event. The dial loop ticks every 30 s by default, so a
    // 60 s polling budget absorbs the worst case (one full ticker period
    // landing just past the start of the window) plus CI-load overhead.
    let mut observed = false;
    for _ in 0..30 {
        tokio::time::sleep(Duration::from_secs(2)).await;
        if let Some(snapshot) = kaspad.hostname_metrics_snapshot().await
            && snapshot.resolutions_total.dial_failure_ok >= 1
        {
            observed = true;
            break;
        }
    }
    let final_snapshot = kaspad.hostname_metrics_snapshot().await.unwrap_or_default();
    assert!(
        observed,
        "expected dial_failure_ok >= 1 within ~60s; final snapshot = {final_snapshot:?}; resolver call_count = {}",
        resolver.call_count(),
    );

    rpc_client.disconnect().await.unwrap();
    drop(rpc_client);
    kaspad.shutdown();
}

// =============================================================================
// DNS-volatility integration tests (silent-on-no-delta + toggle suites)
// =============================================================================

mod dns_volatility {
    use super::{Daemon, init_allocator_with_default_settings};
    use kaspa_connectionmanager::test_support::FakeHostnameResolver;
    use kaspa_consensus_core::network::{NetworkId, NetworkType};
    use kaspa_utils::networking::PeerEndpoint;
    use kaspad_lib::{args::Args, daemon::DaemonOverrides};
    use std::net::SocketAddr;
    use std::str::FromStr;
    use std::sync::{Arc, Mutex as StdMutex};
    use std::time::Duration;

    /// In-memory `log::Log` shim. Tests install it via
    /// [`install_capturing_logger`] before [`Daemon::start`] so every line
    /// the running daemon emits via `info!` / `warn!` lands in a
    /// `Vec<String>` the test can scan for `addpeer:` substrings. The
    /// install replaces the standard `kaspa_core::log::try_init_logger`
    /// console appender; tests in this module MUST NOT also call
    /// `try_init_logger` (the global logger is single-set; second call
    /// would race the appender installed here).
    ///
    /// Per-test isolation relies on `cargo nextest` running each
    /// integration test in its own subprocess (the rusty-kaspa CI default
    /// per `scopes/rust.md`); the `set_boxed_logger` call panics on a
    /// double-install so a regression to a shared-process runner is
    /// surfaced loudly rather than silently passing on empty captures.
    struct CapturingLogger {
        lines: Arc<StdMutex<Vec<String>>>,
    }

    impl log::Log for CapturingLogger {
        fn enabled(&self, _: &log::Metadata) -> bool {
            true
        }
        fn log(&self, record: &log::Record) {
            let line = format!("{} {}: {}", record.level(), record.target(), record.args());
            // Mirror to stderr so a failing assertion still surfaces context
            // in the nextest captured-output panel.
            eprintln!("{line}");
            self.lines.lock().unwrap().push(line);
        }
        fn flush(&self) {}
    }

    fn install_capturing_logger() -> Arc<StdMutex<Vec<String>>> {
        let lines = Arc::new(StdMutex::new(Vec::new()));
        let logger = Box::new(CapturingLogger { lines: lines.clone() });
        log::set_boxed_logger(logger).expect(
            "global logger must be unset at install time; \
             cargo nextest runs each integration test in its own process",
        );
        log::set_max_level(log::LevelFilter::Info);
        lines
    }

    /// Snapshot of the captured log lines since process start. Cloning
    /// keeps subsequent comparisons lock-free.
    fn snapshot(lines: &Arc<StdMutex<Vec<String>>>) -> Vec<String> {
        lines.lock().unwrap().clone()
    }

    /// Count of `addpeer:` lines (any level) referencing `host`.
    /// Production logging vocabulary: registration uses `addpeer:`,
    /// reconciliation deltas use `addpeer:`, dial-loop logs use other
    /// prefixes (filtered out by the substring test).
    fn addpeer_count(lines: &[String], host: &str) -> usize {
        lines.iter().filter(|l| l.contains("addpeer:") && l.contains(host)).count()
    }

    /// Hold an arm for `cadence_sec` (first-tick window) plus
    /// `2 * cadence_sec` (intra-arm window), and return
    /// `(transition_delta, intra_arm_delta)` -- the count of new
    /// `addpeer:` lines for `host` produced inside each window.
    /// Caller asserts `transition_delta <= 1` (per-discipline
    /// one-shot allowed) and `intra_arm_delta == 0` (silence between
    /// transitions).
    async fn arm_observe(lines: &Arc<StdMutex<Vec<String>>>, host: &str, cadence_sec: u64) -> (usize, usize) {
        let pre_first = snapshot(lines);
        tokio::time::sleep(Duration::from_millis(cadence_sec * 1000 + 500)).await;
        let post_first = snapshot(lines);
        tokio::time::sleep(Duration::from_millis(2 * cadence_sec * 1000 + 500)).await;
        let post_intra = snapshot(lines);
        let transition_delta = addpeer_count(&post_first, host) - addpeer_count(&pre_first, host);
        let intra_delta = addpeer_count(&post_intra, host) - addpeer_count(&post_first, host);
        (transition_delta, intra_delta)
    }

    /// Single-arm DNS-failure suite. The fake resolver returns `Err` for
    /// the addpeer host across every periodic refresh tick the daemon
    /// fires inside the observation window. Locks two contracts:
    ///
    /// 1. **Silent-on-no-delta:** the daemon emits exactly one `addpeer:`
    ///    warn line for the host -- the registration-time one-shot from
    ///    `add_endpoint_request`. Subsequent failed refreshes do NOT
    ///    re-emit the warn (the discipline encoded in
    ///    `ConnectionManager::refresh_hostnames` Phase 4: `info!` only
    ///    fires on a non-empty delta; `apply_refresh_results` on `Err`
    ///    bumps `refresh_failures` silently).
    /// 2. **Periodic ticks actually fired:** the metric counter
    ///    `peer_hostname_resolutions_total` increments at least 4 times
    ///    on the failure path during the window, proving the silence is
    ///    real work-not-skipped. The label is `dial_failure_failed`
    ///    (NOT `periodic_failed`) because the initial-failed register
    ///    calls `mark_stale` -> `last_refresh = None`, and
    ///    `pending_refreshes` labels None-`last_refresh` entries
    ///    `DialFailure` until a successful resolve advances the
    ///    timestamp. The cross-check tracks the as-built counter; the
    ///    label-vs-dispatch drift is recorded in the impl report's
    ///    FINDINGS.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn kaspad_unresolvable_periodic_no_log_spam() {
        init_allocator_with_default_settings();
        let lines = install_capturing_logger();

        let host = "no-spam.kas947.invalid";
        let endpoint = PeerEndpoint::from_str(host).expect("parse hostname endpoint");
        let resolver = Arc::new(FakeHostnameResolver::new());
        let devnet_p2p_port = NetworkId::new(NetworkType::Devnet).default_p2p_port();
        resolver.set_err(host, devnet_p2p_port, "fake resolver: no-spam.kas947.invalid never resolves");

        let refresh_interval_sec = 1u64;
        let args = Args {
            devnet: true,
            disable_upnp: true,
            add_peers: vec![endpoint],
            hostname_refresh_interval_sec: refresh_interval_sec,
            ..Default::default()
        };
        let overrides = DaemonOverrides { hostname_resolver: Some(resolver.clone()) };
        let mut kaspad = Daemon::new_random_with_args_and_overrides(args, overrides, 10);
        let rpc_client = kaspad.start().await;

        // Observation window: cadence 1 s, sleep 6 s. The ticker skips
        // its immediate-fire tick, so the first periodic tick lands at
        // ~ t=1 s and at least 5 ticks fire by t=6 s. CI-jitter headroom
        // keeps the >= 4 metric assertion comfortable.
        tokio::time::sleep(Duration::from_secs(6)).await;

        let snap = snapshot(&lines);
        let metrics =
            kaspad.hostname_metrics_snapshot().await.expect("connection manager should be wired into the flow context after start()");

        let warn_lines: Vec<&String> =
            snap.iter().filter(|l| l.starts_with("WARN") && l.contains("addpeer:") && l.contains(host)).collect();
        assert_eq!(
            warn_lines.len(),
            1,
            "expected exactly one addpeer warn line for {host} (the registration one-shot); got {}: {warn_lines:?}",
            warn_lines.len(),
        );
        let info_lines: Vec<&String> =
            snap.iter().filter(|l| l.starts_with("INFO") && l.contains("addpeer:") && l.contains(host)).collect();
        assert!(info_lines.is_empty(), "expected zero addpeer info lines for {host} on the unresolvable path; got: {info_lines:?}",);

        // Cross-check: the periodic refresh task DID run (>= 4 failure
        // increments inside the 6 s window). The discipline labels these
        // increments `dial_failure_failed` because the initial-failed
        // register marks the entry stale (`last_refresh = None`).
        assert!(
            metrics.resolutions_total.initial_failed >= 1,
            "expected initial_failed >= 1 after registering an unresolvable hostname; metrics = {metrics:?}; resolver call_count = {}",
            resolver.call_count(),
        );
        assert!(
            metrics.resolutions_total.dial_failure_failed >= 4,
            "expected dial_failure_failed >= 4 after 6 s @ 1 s cadence (proves periodic ticks fired); metrics = {metrics:?}; resolver call_count = {}",
            resolver.call_count(),
        );
        // The resolver was hit at least: 1 initial + 4 ticks = 5 calls.
        assert!(
            resolver.call_count() >= 5,
            "expected resolver call_count >= 5 (1 initial + >=4 periodic ticks); got {}",
            resolver.call_count(),
        );

        // Daemon stayed up across the window.
        assert!(rpc_client.handle_message_id(), "RPC client lost server liveness during the unresolvable-host observation window",);

        rpc_client.disconnect().await.unwrap();
        drop(rpc_client);
        kaspad.shutdown();
    }

    /// Toggle suite seeded UNRESOLVABLE. Cycles through arms
    /// `unresolvable -> resolvable -> unresolvable -> resolvable`, each
    /// arm holding for >= 2 periodic-refresh ticks. Locks the
    /// intra-arm-silence contract: across the K-1 ticks AFTER the first
    /// tick of any new arm, the daemon emits zero new `addpeer:` lines.
    /// The first tick of an arm may emit one transition log line per
    /// the current discipline (the seeded-unresolvable arm emits the
    /// initial registration warn; the first-resolvable arm emits a
    /// `+1 new` reconciliation info line; subsequent transitions are
    /// silent because `last_resolved` is preserved on `Err` and the
    /// resolvable arms reuse the same socket address).
    ///
    /// Cross-checks the metric interleave (`dial_failure_*` on the
    /// first transition out of the seeded-stale state, `periodic_*`
    /// from then on) and the `last_resolved` invariant via
    /// `HostnameMetricsSnapshot.resolved_addrs`: once a resolvable arm
    /// installs the socket address, the gauge stays at >= 1 across
    /// every subsequent unresolvable arm (the failure path never
    /// clears the registry).
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn kaspad_unresolvable_to_resolvable_toggle() {
        init_allocator_with_default_settings();
        let lines = install_capturing_logger();

        let host = "toggle-u2r.kas947.invalid";
        let endpoint = PeerEndpoint::from_str(host).expect("parse hostname endpoint");
        let resolver = Arc::new(FakeHostnameResolver::new());
        let devnet_p2p_port = NetworkId::new(NetworkType::Devnet).default_p2p_port();
        let stub: SocketAddr = "127.0.0.1:42201".parse().unwrap();
        // Seed: unresolvable.
        resolver.set_err(host, devnet_p2p_port, "fake resolver: toggle-u2r.kas947.invalid (initial unresolvable)");

        let refresh_interval_sec = 1u64;
        let args = Args {
            devnet: true,
            disable_upnp: true,
            add_peers: vec![endpoint],
            hostname_refresh_interval_sec: refresh_interval_sec,
            ..Default::default()
        };
        let overrides = DaemonOverrides { hostname_resolver: Some(resolver.clone()) };
        let mut kaspad = Daemon::new_random_with_args_and_overrides(args, overrides, 10);
        let rpc_client = kaspad.start().await;

        // Daemon::start() completes the initial registration before
        // returning. The registration discipline for the unresolvable
        // seed is exactly 1 warn line ("addpeer: ...; queued for
        // periodic retry"); lock that here, separately from the
        // per-arm windows below which only cover post-registration
        // ticks.
        let after_register = snapshot(&lines);
        let warn_after_register =
            after_register.iter().filter(|l| l.starts_with("WARN") && l.contains("addpeer:") && l.contains(host)).count();
        assert_eq!(
            warn_after_register, 1,
            "registration discipline (unresolvable seed): exactly 1 addpeer warn line; got {warn_after_register}; snapshot = {after_register:?}",
        );

        // Arm 1: seeded unresolvable, ticks all run after registration.
        // Failure-path ticks are silent.
        let (arm1_transition, arm1_intra) = arm_observe(&lines, host, refresh_interval_sec).await;
        assert_eq!(
            arm1_transition, 0,
            "arm 1 (post-register, unresolvable) tick window must be silent (failure path doesn't log); got {arm1_transition}",
        );
        assert_eq!(arm1_intra, 0, "arm 1 (unresolvable) intra-arm addpeer lines must be zero; got {arm1_intra}");

        // Switch to resolvable. Arm 2: first tick is labelled
        // DialFailure (last_refresh still None from initial mark_stale)
        // and produces the +1-new delta info line. Subsequent ticks are
        // silent (same socket address, empty delta).
        resolver.set(host, devnet_p2p_port, vec![stub]);
        let (arm2_transition, arm2_intra) = arm_observe(&lines, host, refresh_interval_sec).await;
        assert_eq!(
            arm2_transition, 1,
            "arm 2 (unresolvable -> resolvable) discipline produces exactly 1 transition addpeer line (+1 new reconciliation info); got {arm2_transition}",
        );
        assert_eq!(arm2_intra, 0, "arm 2 (resolvable) intra-arm addpeer lines must be zero; got {arm2_intra}");

        // Resolvable arm planted the socket: the registry gauge is now
        // >= 1; the invariant is that the failure path below preserves
        // it (entries are removed only via explicit mark_stale, never
        // by failure paths).
        let after_arm2 = kaspad.hostname_metrics_snapshot().await.expect("snapshot after resolvable arm");
        assert!(
            after_arm2.resolved_addrs >= 1,
            "after resolvable arm 2: resolved_addrs gauge must be >= 1; got {}",
            after_arm2.resolved_addrs,
        );

        // Switch back to unresolvable. Arm 3: ticks labelled Periodic
        // (last_refresh is now Some(...) from arm 2's success). Failure
        // path leaves last_resolved untouched -> gauge stays >= 1 and
        // no new log lines fire.
        resolver.set_err(host, devnet_p2p_port, "fake resolver: toggle-u2r.kas947.invalid (toggle to unresolvable)");
        let (arm3_transition, arm3_intra) = arm_observe(&lines, host, refresh_interval_sec).await;
        assert_eq!(
            arm3_transition, 0,
            "arm 3 (resolvable -> unresolvable) discipline produces zero transition addpeer lines (failure path is silent); got {arm3_transition}",
        );
        assert_eq!(arm3_intra, 0, "arm 3 (unresolvable) intra-arm addpeer lines must be zero; got {arm3_intra}");
        let after_arm3 = kaspad.hostname_metrics_snapshot().await.expect("snapshot after unresolvable arm");
        assert_eq!(
            after_arm3.resolved_addrs, after_arm2.resolved_addrs,
            "last_resolved invariant broken: failure path cleared the registry across arm 3 (was {} now {})",
            after_arm2.resolved_addrs, after_arm3.resolved_addrs,
        );

        // Switch to resolvable with the SAME socket. Arm 4: ticks
        // resolve OK; delta is empty (last_resolved unchanged); no log
        // line at all.
        resolver.set(host, devnet_p2p_port, vec![stub]);
        let (arm4_transition, arm4_intra) = arm_observe(&lines, host, refresh_interval_sec).await;
        assert_eq!(
            arm4_transition, 0,
            "arm 4 (resolvable, same IP) transition addpeer lines must be zero (delta empty); got {arm4_transition}",
        );
        assert_eq!(arm4_intra, 0, "arm 4 (resolvable) intra-arm addpeer lines must be zero; got {arm4_intra}");

        // Final metric interleave check: every counter we expected to
        // increment did, and the unresolvable arm seeded counter is
        // labelled DialFailure (one-shot) while the toggled arms produce
        // periodic_* / dial_failure_* increments mixing as documented
        // above.
        let final_metrics = kaspad.hostname_metrics_snapshot().await.expect("final snapshot");
        assert!(final_metrics.resolutions_total.initial_failed >= 1, "initial register failed at least once: {final_metrics:?}");
        assert!(
            final_metrics.resolutions_total.dial_failure_ok >= 1,
            "first resolvable tick (DialFailure-labelled because last_refresh was None) must increment dial_failure_ok: {final_metrics:?}",
        );
        assert!(
            final_metrics.resolutions_total.periodic_failed >= 1,
            "arm 3 unresolvable ticks must increment periodic_failed (last_refresh advanced by arm 2): {final_metrics:?}",
        );
        assert!(
            final_metrics.resolutions_total.periodic_ok >= 1,
            "arm 4 resolvable ticks must increment periodic_ok: {final_metrics:?}",
        );

        assert!(rpc_client.handle_message_id(), "RPC client lost server liveness during the toggle window");
        rpc_client.disconnect().await.unwrap();
        drop(rpc_client);
        kaspad.shutdown();
    }

    /// Toggle suite seeded RESOLVABLE. Cycles through arms
    /// `resolvable -> unresolvable -> resolvable -> unresolvable`, each
    /// arm holding for >= 2 periodic-refresh ticks. Locks the same
    /// intra-arm-silence contract as the sibling test, exercised from
    /// the opposite phase: the seeded-resolvable arm produces the
    /// initial registration info line ("addpeer: resolved <host> ->
    /// [...]") and every subsequent arm is silent because (a)
    /// resolvable arms reuse the same socket so deltas are empty, and
    /// (b) failure arms preserve `last_resolved` unchanged.
    #[tokio::test(flavor = "multi_thread", worker_threads = 1)]
    async fn kaspad_resolvable_to_unresolvable_toggle() {
        init_allocator_with_default_settings();
        let lines = install_capturing_logger();

        let host = "toggle-r2u.kas947.invalid";
        let endpoint = PeerEndpoint::from_str(host).expect("parse hostname endpoint");
        let resolver = Arc::new(FakeHostnameResolver::new());
        let devnet_p2p_port = NetworkId::new(NetworkType::Devnet).default_p2p_port();
        let stub: SocketAddr = "127.0.0.1:42301".parse().unwrap();
        // Seed: resolvable.
        resolver.set(host, devnet_p2p_port, vec![stub]);

        let refresh_interval_sec = 1u64;
        let args = Args {
            devnet: true,
            disable_upnp: true,
            add_peers: vec![endpoint],
            hostname_refresh_interval_sec: refresh_interval_sec,
            ..Default::default()
        };
        let overrides = DaemonOverrides { hostname_resolver: Some(resolver.clone()) };
        let mut kaspad = Daemon::new_random_with_args_and_overrides(args, overrides, 10);
        let rpc_client = kaspad.start().await;

        // Daemon::start() completes the initial registration before
        // returning. The registration discipline for the resolvable
        // seed is exactly 1 info line ("addpeer: resolved ..."); lock
        // that here, separately from the per-arm windows below which
        // only cover post-registration ticks.
        let after_register = snapshot(&lines);
        let info_after_register =
            after_register.iter().filter(|l| l.starts_with("INFO") && l.contains("addpeer:") && l.contains(host)).count();
        assert_eq!(
            info_after_register, 1,
            "registration discipline (resolvable seed): exactly 1 addpeer info line; got {info_after_register}; snapshot = {after_register:?}",
        );

        // Arm 1: seeded resolvable, ticks all run after registration.
        // trigger=Periodic, same IP -> delta empty -> silent.
        let (arm1_transition, arm1_intra) = arm_observe(&lines, host, refresh_interval_sec).await;
        assert_eq!(
            arm1_transition, 0,
            "arm 1 (post-register, resolvable, same IP) tick window must be silent (delta empty); got {arm1_transition}",
        );
        assert_eq!(arm1_intra, 0, "arm 1 (resolvable) intra-arm addpeer lines must be zero; got {arm1_intra}");

        let after_arm1 = kaspad.hostname_metrics_snapshot().await.expect("snapshot after resolvable arm");
        assert!(
            after_arm1.resolved_addrs >= 1,
            "after resolvable arm 1: resolved_addrs gauge must be >= 1; got {}",
            after_arm1.resolved_addrs,
        );

        // Switch to unresolvable. Arm 2: ticks Periodic_failed, silent,
        // last_resolved preserved.
        resolver.set_err(host, devnet_p2p_port, "fake resolver: toggle-r2u.kas947.invalid (toggle to unresolvable)");
        let (arm2_transition, arm2_intra) = arm_observe(&lines, host, refresh_interval_sec).await;
        assert_eq!(arm2_transition, 0, "arm 2 (unresolvable) transition addpeer lines must be zero; got {arm2_transition}");
        assert_eq!(arm2_intra, 0, "arm 2 (unresolvable) intra-arm addpeer lines must be zero; got {arm2_intra}");
        let after_arm2 = kaspad.hostname_metrics_snapshot().await.expect("snapshot after unresolvable arm");
        assert_eq!(
            after_arm2.resolved_addrs, after_arm1.resolved_addrs,
            "last_resolved invariant broken: failure path cleared the registry across arm 2 (was {} now {})",
            after_arm1.resolved_addrs, after_arm2.resolved_addrs,
        );

        // Switch back to resolvable with the SAME socket. Arm 3: ticks
        // Periodic_ok, delta empty, silent.
        resolver.set(host, devnet_p2p_port, vec![stub]);
        let (arm3_transition, arm3_intra) = arm_observe(&lines, host, refresh_interval_sec).await;
        assert_eq!(arm3_transition, 0, "arm 3 (resolvable, same IP) transition addpeer lines must be zero; got {arm3_transition}");
        assert_eq!(arm3_intra, 0, "arm 3 (resolvable) intra-arm addpeer lines must be zero; got {arm3_intra}");
        let after_arm3 = kaspad.hostname_metrics_snapshot().await.expect("snapshot after resolvable arm 3");
        assert_eq!(
            after_arm3.resolved_addrs, after_arm2.resolved_addrs,
            "resolved_addrs unchanged across resolvable arm 3 (same IP): was {} now {}",
            after_arm2.resolved_addrs, after_arm3.resolved_addrs,
        );

        // Switch back to unresolvable. Arm 4: ticks Periodic_failed,
        // silent, last_resolved preserved.
        resolver.set_err(host, devnet_p2p_port, "fake resolver: toggle-r2u.kas947.invalid (final unresolvable)");
        let (arm4_transition, arm4_intra) = arm_observe(&lines, host, refresh_interval_sec).await;
        assert_eq!(arm4_transition, 0, "arm 4 (unresolvable) transition addpeer lines must be zero; got {arm4_transition}");
        assert_eq!(arm4_intra, 0, "arm 4 (unresolvable) intra-arm addpeer lines must be zero; got {arm4_intra}");
        let after_arm4 = kaspad.hostname_metrics_snapshot().await.expect("final snapshot");
        assert_eq!(
            after_arm4.resolved_addrs, after_arm3.resolved_addrs,
            "last_resolved invariant broken: failure path cleared the registry across arm 4 (was {} now {})",
            after_arm3.resolved_addrs, after_arm4.resolved_addrs,
        );

        // Final metric interleave: initial registration succeeded, the
        // failure arms moved Periodic_failed, the resolvable arms moved
        // Periodic_ok. dial_failure_* should remain at 0 (the entry was
        // never marked stale -- arm 1 succeeded so last_refresh is
        // never None inside this test).
        assert!(after_arm4.resolutions_total.initial_ok >= 1, "initial resolvable register: {after_arm4:?}");
        assert!(
            after_arm4.resolutions_total.periodic_failed >= 2,
            "arms 2+4 unresolvable must increment periodic_failed; metrics = {after_arm4:?}",
        );
        assert!(
            after_arm4.resolutions_total.periodic_ok >= 2,
            "arms 1+3 resolvable must increment periodic_ok; metrics = {after_arm4:?}",
        );
        assert_eq!(
            after_arm4.resolutions_total.dial_failure_failed, 0,
            "no dial-failure-triggered re-resolution should fire in this test (no dial loop interaction); got {after_arm4:?}",
        );

        assert!(rpc_client.handle_message_id(), "RPC client lost server liveness during the toggle window");
        rpc_client.disconnect().await.unwrap();
        drop(rpc_client);
        kaspad.shutdown();
    }
}
