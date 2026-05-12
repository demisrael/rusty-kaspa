//! Binary entry point. The 17-subcommand surface is wired via
//! `clap`; subcommands route to the in-crate `dispatch` module
//! (offline subcommands compose the library directly; daemon-
//! client subcommands dial the running daemon via the in-crate
//! `DaemonClient`). `parse` reads transaction hex offline and
//! emits the transcript via the library's parse module;
//! `start-daemon` boots the gRPC daemon surface via the
//! library's daemon module.

use std::io::{self, Write};
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;

use kaspawallet::cli::{Cli, ParseArgs, StartDaemonArgs, Subcommand};
use kaspawallet::daemon::{ServeOptions, start_daemon};
use kaspawallet::dispatch;
use kaspawallet::keyfile;
use kaspawallet::keysource::require_existing_keyfile;
use kaspawallet::parse::{ParseInput, parse};
use kaspawallet::version;

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Subcommand::Version(_) => {
            version::print();
            ExitCode::SUCCESS
        }
        Subcommand::Create(args) => dispatch::run_create(args, &cli.network),
        Subcommand::DumpUnencryptedData(args) => dispatch::run_dump_unencrypted_data(args, &cli.network),
        Subcommand::StartDaemon(args) => run_start_daemon(args, &cli.network),
        Subcommand::Balance(args) => dispatch::run_balance(args, &cli.network),
        Subcommand::Send(args) => dispatch::run_send(args, &cli.network),
        Subcommand::CreateUnsignedTransaction(args) => dispatch::run_create_unsigned_transaction(args, &cli.network),
        Subcommand::Sign(args) => dispatch::run_sign(args, &cli.network),
        Subcommand::Broadcast(args) => dispatch::run_broadcast(args, &cli.network),
        Subcommand::Parse(args) => run_parse(args, &cli.network),
        Subcommand::ShowAddresses(args) => dispatch::run_show_addresses(args, &cli.network),
        Subcommand::NewAddress(args) => dispatch::run_new_address(args, &cli.network),
        Subcommand::Sweep(args) => dispatch::run_sweep(args, &cli.network),
        Subcommand::BroadcastReplacement(args) => dispatch::run_broadcast_replacement(args, &cli.network),
        Subcommand::BumpFee(args) => dispatch::run_bump_fee(args, &cli.network),
        Subcommand::BumpFeeUnsigned(args) => dispatch::run_bump_fee_unsigned(args, &cli.network),
        Subcommand::GetDaemonVersion(args) => dispatch::run_get_daemon_version(args),
    }
}

fn run_start_daemon(args: StartDaemonArgs, top_level_network: &kaspawallet::cli::NetworkFlags) -> ExitCode {
    if !args.wallet_backend.is_available() {
        eprintln!("wallet backend '{}' is not available in this build", args.wallet_backend.as_kebab());
        return ExitCode::from(2);
    }
    let mut merged = top_level_network.clone();
    merged.combine(&args.network);
    let override_path = args.keys_file.as_deref().map(Path::new);
    let keysfile_path = match require_existing_keyfile(override_path, merged.network_name()) {
        Ok(p) => p,
        Err(err) => {
            let _ = writeln!(io::stderr(), "{err}");
            return ExitCode::from(1);
        }
    };
    let opts = ServeOptions {
        listen: args.listen,
        keysfile_path,
        rpcserver: args.rpcserver,
        address_prefix: merged.address_prefix(),
        version: env!("CARGO_PKG_VERSION").to_owned(),
    };
    let runtime = match tokio::runtime::Builder::new_multi_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(err) => {
            let _ = writeln!(io::stderr(), "failed to build tokio runtime: {err}");
            return ExitCode::from(1);
        }
    };
    match runtime.block_on(start_daemon(opts)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            let _ = writeln!(io::stderr(), "{err}");
            ExitCode::from(1)
        }
    }
}

fn run_parse(args: ParseArgs, top_level_network: &kaspawallet::cli::NetworkFlags) -> ExitCode {
    if !args.wallet_backend.is_available() {
        eprintln!("wallet backend '{}' is not available in this build", args.wallet_backend.as_kebab());
        return ExitCode::from(2);
    }
    // Merge top-level + per-subcommand network flags.
    let mut merged = top_level_network.clone();
    merged.combine(&args.network);

    // Resolve the keyfile path: operator-supplied `--keys-file`
    // override if present, otherwise the platform-aware default
    // (`<app-dir>/<network>/keys.json`). The keyfile is ALWAYS
    // read; failure at the resolved path exits 1 with a
    // structured error.
    let override_path = args.keys_file.as_deref().map(Path::new);
    let keysfile_path = match require_existing_keyfile(override_path, merged.network_name()) {
        Ok(p) => p,
        Err(err) => {
            let _ = writeln!(io::stderr(), "{err}");
            return ExitCode::from(1);
        }
    };
    let keysfile = match keyfile::read_from_path(&keysfile_path) {
        Ok(kf) => kf,
        Err(err) => {
            let _ = writeln!(io::stderr(), "{err}");
            return ExitCode::from(1);
        }
    };

    let input = ParseInput {
        transaction: args.transaction.as_deref(),
        transaction_file: args.transaction_file.as_deref(),
        verbose: args.verbose,
        network: &merged,
        keysfile: Some(&keysfile),
    };

    let stdout = io::stdout();
    let mut handle = stdout.lock();
    match parse(&input, &mut handle) {
        Ok(_) => {
            let _ = handle.flush();
            ExitCode::SUCCESS
        }
        Err(err) => {
            let _ = writeln!(io::stderr(), "{err}");
            ExitCode::from(1)
        }
    }
}
