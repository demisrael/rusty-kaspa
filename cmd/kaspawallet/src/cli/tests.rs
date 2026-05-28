//! Subcommand-registry and flag-parity tests.

use clap::CommandFactory;

use super::args::Cli;
use super::wallet_backend::WalletBackend;

/// The full 17-subcommand surface registered on the binary's
/// `clap` `Command`.
const EXPECTED_SUBCOMMANDS: &[&str] = &[
    "create",
    "dump-unencrypted-data",
    "start-daemon",
    "balance",
    "send",
    "create-unsigned-transaction",
    "sign",
    "broadcast",
    "parse",
    "show-addresses",
    "new-address",
    "version",
    "sweep",
    "broadcast-replacement",
    "bump-fee",
    "bump-fee-unsigned",
    "get-daemon-version",
];

#[test]
fn test_subcommand_registry_matches_go_set() {
    let mut cmd = Cli::command();
    let mut got: Vec<String> = cmd.get_subcommands_mut().map(|s| s.get_name().to_string()).collect();
    got.sort();
    let mut want: Vec<String> = EXPECTED_SUBCOMMANDS.iter().map(|s| (*s).to_string()).collect();
    want.sort();
    assert_eq!(got, want, "registered subcommands deviate from the expected surface");
}

#[test]
fn test_subcommand_count_is_seventeen() {
    let cmd = Cli::command();
    let count = cmd.get_subcommands().count();
    assert_eq!(count, 17, "wallet binary exposes exactly 17 subcommands");
}

#[test]
fn test_create_flag_parity_with_go() {
    let cmd = Cli::command();
    let sub = cmd.find_subcommand("create").expect("create subcommand registered");
    let longs: Vec<&str> = sub.get_arguments().filter_map(|a| a.get_long()).collect();
    let expected = [
        "keys-file",
        "password",
        "yes",
        "min-signatures",
        "num-private-keys",
        "num-public-keys",
        "ecdsa",
        "import",
        "wallet-backend",
        // network-flag group:
        "testnet",
        "simnet",
        "devnet",
        "override-dag-params-file",
    ];
    for ex in &expected {
        assert!(longs.contains(ex), "create is missing flag --{ex}: {longs:?}");
    }
}

#[test]
fn test_send_required_to_address() {
    let cmd = Cli::command();
    let sub = cmd.find_subcommand("send").expect("send subcommand registered");
    let to_address = sub.get_arguments().find(|a| a.get_long() == Some("to-address")).expect("send has --to-address");
    assert!(to_address.is_required_set(), "send --to-address must be required");
}

#[test]
fn test_create_unsigned_required_to_address() {
    let cmd = Cli::command();
    let sub = cmd.find_subcommand("create-unsigned-transaction").expect("create-unsigned-transaction registered");
    let to_address = sub.get_arguments().find(|a| a.get_long() == Some("to-address")).expect("subcommand has --to-address");
    assert!(to_address.is_required_set(), "create-unsigned-transaction --to-address must be required");
}

#[test]
fn test_balance_daemon_address_default_is_loopback() {
    let cmd = Cli::command();
    let sub = cmd.find_subcommand("balance").expect("balance subcommand registered");
    let arg = sub.get_arguments().find(|a| a.get_long() == Some("daemonaddress")).expect("balance has --daemonaddress");
    let defaults: Vec<&clap::builder::OsStr> = arg.get_default_values().iter().collect();
    let default_os: &std::ffi::OsStr = defaults.first().expect("default present").as_ref();
    let default_str = default_os.to_str().unwrap_or("");
    assert_eq!(default_str, "localhost:8082", "daemon address default must be loopback-only");
}

#[test]
fn test_start_daemon_listen_default_is_loopback() {
    let cmd = Cli::command();
    let sub = cmd.find_subcommand("start-daemon").expect("start-daemon subcommand registered");
    let arg = sub.get_arguments().find(|a| a.get_long() == Some("listen")).expect("start-daemon has --listen");
    let defaults: Vec<&clap::builder::OsStr> = arg.get_default_values().iter().collect();
    let default_os: &std::ffi::OsStr = defaults.first().expect("default present").as_ref();
    let default_str = default_os.to_str().unwrap_or("");
    assert_eq!(default_str, "localhost:8082", "--listen default must be localhost:8082");
}

#[test]
fn test_wallet_backend_flag_appears_only_on_keyfile_subcommands() {
    let cmd = Cli::command();
    let with_backend = ["create", "dump-unencrypted-data", "start-daemon", "sign", "parse", "sweep"];
    let without_backend = [
        "balance",
        "send",
        "create-unsigned-transaction",
        "broadcast",
        "show-addresses",
        "new-address",
        "version",
        "broadcast-replacement",
        "bump-fee",
        "bump-fee-unsigned",
        "get-daemon-version",
    ];

    for name in &with_backend {
        let sub = cmd.find_subcommand(name).expect("subcommand registered");
        let has_flag = sub.get_arguments().any(|a| a.get_long() == Some("wallet-backend"));
        assert!(has_flag, "subcommand {name} must carry --wallet-backend");
    }
    for name in &without_backend {
        let sub = cmd.find_subcommand(name).expect("subcommand registered");
        let has_flag = sub.get_arguments().any(|a| a.get_long() == Some("wallet-backend"));
        assert!(!has_flag, "subcommand {name} must NOT carry --wallet-backend (daemon-client or version)");
    }
}

#[test]
fn test_wallet_backend_default_is_go() {
    let cmd = Cli::command();
    let sub = cmd.find_subcommand("create").expect("create subcommand registered");
    let arg = sub.get_arguments().find(|a| a.get_long() == Some("wallet-backend")).expect("create has --wallet-backend");
    let defaults: Vec<&clap::builder::OsStr> = arg.get_default_values().iter().collect();
    let default_os_str: &std::ffi::OsStr = defaults.first().expect("default present").as_ref();
    let default_str = default_os_str.to_str().unwrap_or("");
    assert_eq!(default_str, "go", "default backend must be go");
}

#[test]
fn test_wallet_backend_kebab_round_trip() {
    assert_eq!(WalletBackend::Go.as_kebab(), "go");
    assert_eq!(WalletBackend::Kdx.as_kebab(), "kdx");
    assert_eq!(WalletBackend::Tangem.as_kebab(), "tangem");
    assert_eq!(WalletBackend::Ledger.as_kebab(), "ledger");
    assert_eq!(WalletBackend::KaspaNg.as_kebab(), "kaspa-ng");
    assert!(WalletBackend::Go.is_available());
    assert!(!WalletBackend::Kdx.is_available());
    assert!(!WalletBackend::Tangem.is_available());
    assert!(!WalletBackend::Ledger.is_available());
    assert!(!WalletBackend::KaspaNg.is_available());
}

#[test]
fn test_short_flag_no_conflicts_within_each_subcommand() {
    let cmd = Cli::command();
    for sub in cmd.get_subcommands() {
        let mut seen = std::collections::HashSet::new();
        for arg in sub.get_arguments() {
            if let Some(short) = arg.get_short()
                && !seen.insert(short)
            {
                panic!("subcommand {} reuses short flag -{short}", sub.get_name());
            }
        }
    }
}

#[test]
fn test_subcommand_parsing_smoke() {
    use clap::Parser;

    // `version` parses with zero flags.
    let cli = Cli::try_parse_from(["kaspawallet", "version"]).expect("version parses");
    assert!(matches!(cli.command, super::Subcommand::Version(_)));

    // `send --to-address kaspa:...` parses.
    let cli = Cli::try_parse_from(["kaspawallet", "send", "--to-address", "kaspa:qabcd", "--send-amount", "1.5"])
        .expect("send parses with mandatory to-address");
    if let super::Subcommand::Send(args) = cli.command {
        assert_eq!(args.to_address, "kaspa:qabcd");
        assert_eq!(args.send_amount.as_deref(), Some("1.5"));
    } else {
        panic!("expected Send subcommand");
    }

    // `send` without --to-address fails.
    let err = Cli::try_parse_from(["kaspawallet", "send", "--send-amount", "1"]).expect_err("missing required");
    let s = format!("{err}");
    assert!(s.contains("to-address"), "missing-required error must name --to-address: {s}");

    // `create --wallet-backend ledger` parses (resolver enforces availability later).
    let cli = Cli::try_parse_from(["kaspawallet", "create", "--wallet-backend", "ledger", "--yes"])
        .expect("ledger backend parses even though it is reserved");
    if let super::Subcommand::Create(args) = cli.command {
        assert_eq!(args.wallet_backend, WalletBackend::Ledger);
    } else {
        panic!("expected Create subcommand");
    }
}

#[test]
fn test_rbf_subcommands_parse_with_expected_flags() {
    use clap::Parser;

    let cli = Cli::try_parse_from([
        "kaspawallet",
        "bump-fee",
        "--txid",
        "deadbeef",
        "--password",
        "pw",
        "--max-fee-rate",
        "12.5",
        "--show-serialized",
    ])
    .expect("bump-fee parses");
    if let super::Subcommand::BumpFee(args) = cli.command {
        assert_eq!(args.txid.as_deref(), Some("deadbeef"));
        assert_eq!(args.password.as_deref(), Some("pw"));
        assert_eq!(args.max_fee_rate, Some(12.5));
        assert!(args.show_serialized);
    } else {
        panic!("expected BumpFee subcommand");
    }

    let cli = Cli::try_parse_from(["kaspawallet", "bump-fee-unsigned", "--txid", "feedface", "--fee-rate", "3.0"])
        .expect("bump-fee-unsigned parses");
    if let super::Subcommand::BumpFeeUnsigned(args) = cli.command {
        assert_eq!(args.txid.as_deref(), Some("feedface"));
        assert_eq!(args.fee_rate, Some(3.0));
    } else {
        panic!("expected BumpFeeUnsigned subcommand");
    }

    let cli =
        Cli::try_parse_from(["kaspawallet", "broadcast-replacement", "--transaction", "00ff"]).expect("broadcast-replacement parses");
    if let super::Subcommand::BroadcastReplacement(args) = cli.command {
        assert_eq!(args.transaction.as_deref(), Some("00ff"));
    } else {
        panic!("expected BroadcastReplacement subcommand");
    }

    let cli = Cli::try_parse_from(["kaspawallet", "get-daemon-version"]).expect("get-daemon-version parses with defaults");
    if let super::Subcommand::GetDaemonVersion(args) = cli.command {
        assert_eq!(args.daemon_address, super::args::DEFAULT_LISTEN);
    } else {
        panic!("expected GetDaemonVersion subcommand");
    }
}
