//! Standalone-CLI subcommand dispatchers. Each `run_<name>` function
//! is invoked by `main.rs` after `clap` has resolved the per-
//! subcommand argument struct; the function performs the same flow
//! the Go `cmd/kaspawallet/<name>.go` counterpart performs.
//!
//! Offline subcommands (`sign`, `dump-unencrypted-data`, `create`,
//! `sweep` partial) read or write the keyfile directly. Daemon-
//! client subcommands (`balance`, `send`, `create-unsigned-
//! transaction`, `broadcast`, `show-addresses`, `new-address`) dial
//! a running daemon at `--daemonaddress` via the in-crate
//! [`DaemonClient`](crate::daemon::DaemonClient) wrapper.
//!
//! Password handling: the Go binary prompts via terminal when
//! `--password` is empty; the Phase 1 Rust port requires the flag
//! to be supplied non-interactively. Interactive `rpassword`-style
//! prompts are a deliberate follow-on. Scripted / piped operator
//! flows (the common automation case) work today.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::str::FromStr;
use std::time::Duration;

use kaspa_bip32::{
    DerivationPath, ExtendedPrivateKey, ExtendedPublicKey, Language, Mnemonic, Prefix as Bip32Prefix, SecretKey, WordCount,
};
use kaspa_consensus_core::network::NetworkType;
use tonic::Request;
use zeroize::Zeroizing;

use crate::cli::{
    BalanceArgs, BroadcastArgs, BumpFeeArgs, BumpFeeUnsignedArgs, CreateArgs, CreateUnsignedTransactionArgs, DumpUnencryptedDataArgs,
    GetDaemonVersionArgs, NetworkFlags, NewAddressArgs, SendArgs, ShowAddressesArgs, SignArgs, SweepArgs, WalletBackend,
};
use crate::daemon::DaemonClient;
use crate::daemon::pb::{
    BroadcastRequest, BumpFeeRequest, CreateUnsignedTransactionsRequest, FeePolicy, GetBalanceRequest,
    GetExternalSpendableUtxOsRequest, NewAddressRequest, ShowAddressesRequest, fee_policy,
};
use crate::keyfile::{self, KeysFile, LATEST_VERSION};
use crate::keysource::{default_keys_file, require_existing_keyfile};
use crate::serialization;
use crate::sign::{is_pst_fully_signed, sign_pst_ecdsa_with_mnemonic, sign_pst_schnorr_with_mnemonic};
use crate::transactions_hex::{decode_transactions_from_hex, encode_transactions_to_hex};

/// Default per-RPC wait timeout. Matches Go
/// `cmd/kaspawallet/daemon_client.go::daemonTimeout = 2 *
/// time.Minute`.
const DAEMON_TIMEOUT: Duration = Duration::from_secs(120);

/// Sompi-per-kaspa multiplier mirroring Go
/// `domain/consensus/utils/constants.SompiPerKaspa = 100_000_000`.
const SOMPI_PER_KASPA: u64 = 100_000_000;

/// Per-input fee for sweep transactions. Matches Go
/// `cmd/kaspawallet/sweep.go::feePerInput = 10000`.
const SWEEP_FEE_PER_INPUT: u64 = 10_000;

/// BIP-43 purpose component for single-signer wallets. Source:
/// `cmd/kaspawallet/libkaspawallet/bip39.go::SingleSignerPurpose = 44`.
const SINGLE_SIGNER_PURPOSE: u32 = 44;

/// BIP-43-style purpose component for multisig wallets. Source:
/// `cmd/kaspawallet/libkaspawallet/bip39.go::MultiSigPurpose = 45`.
const MULTISIG_PURPOSE: u32 = 45;

/// Kaspa SLIP-0044 coin type. Source:
/// `cmd/kaspawallet/libkaspawallet/bip39.go::CoinType = 111111`.
const COIN_TYPE: u32 = 111111;

// ---- shared helpers -------------------------------------------------

fn merge_network(top: &NetworkFlags, sub: &NetworkFlags) -> NetworkFlags {
    let mut merged = top.clone();
    merged.combine(sub);
    merged
}

fn fail(msg: impl AsRef<str>) -> ExitCode {
    let _ = writeln!(io::stderr(), "{}", msg.as_ref());
    ExitCode::from(1)
}

fn require_backend_available(backend: WalletBackend) -> Result<(), ExitCode> {
    if !backend.is_available() {
        let _ = writeln!(io::stderr(), "wallet backend '{}' is not available in this build", backend.as_kebab());
        return Err(ExitCode::from(2));
    }
    Ok(())
}

fn require_password(password: &Option<String>, subcommand: &str) -> Result<Zeroizing<String>, ExitCode> {
    match password {
        Some(p) if !p.is_empty() => Ok(Zeroizing::new(p.clone())),
        _ => Err(fail(format!(
            "'{subcommand}' requires --password to be supplied; interactive password prompts are a Phase-2 enhancement of the Rust port",
        ))),
    }
}

fn resolve_transaction_hex(transaction: Option<&str>, transaction_file: Option<&str>, subcommand: &str) -> Result<String, ExitCode> {
    match (transaction, transaction_file) {
        (None, None) => Err(fail(format!("'{subcommand}': either --transaction or --transaction-file is required"))),
        (Some(_), Some(_)) => Err(fail(format!("'{subcommand}': --transaction and --transaction-file are mutually exclusive"))),
        (Some(hex), None) => Ok(hex.to_owned()),
        (None, Some(path)) => fs::read_to_string(path)
            .map(|s| s.trim().to_owned())
            .map_err(|e| fail(format!("'{subcommand}': could not read --transaction-file '{path}': {e}"))),
    }
}

fn build_runtime() -> Result<tokio::runtime::Runtime, ExitCode> {
    tokio::runtime::Builder::new_multi_thread().enable_all().build().map_err(|e| fail(format!("failed to build tokio runtime: {e}")))
}

fn read_keyfile(network: &NetworkFlags, keys_override: Option<&str>) -> Result<(KeysFile, PathBuf), ExitCode> {
    let override_path = keys_override.map(Path::new);
    let resolved = require_existing_keyfile(override_path, network.network_name()).map_err(|e| fail(format!("{e}")))?;
    let kf = keyfile::read_from_path(&resolved).map_err(|e| fail(format!("{e}")))?;
    Ok((kf, resolved))
}

fn parse_kas_to_sompi(amount: &str) -> Result<u64, String> {
    // Mirror Go `utils.KasToSompi`: validate `^([1-9]\d{0,11}|0)(\.\d{0,8})?$`,
    // then scale to sompi. Implemented locally to avoid pulling regex
    // for a single shape.
    if amount.is_empty() {
        return Err("invalid amount: empty".to_owned());
    }
    let (int_part, frac_part) = match amount.split_once('.') {
        Some((a, b)) => (a, b),
        None => (amount, ""),
    };
    if int_part != "0" && !(int_part.starts_with(|c: char| c.is_ascii_digit() && c != '0') && int_part.len() <= 12) {
        return Err(format!("invalid amount '{amount}': integer part must be 0 or a 1-12 digit non-leading-zero integer"));
    }
    if !int_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("invalid amount '{amount}': non-digit in integer part"));
    }
    if frac_part.len() > 8 || !frac_part.chars().all(|c| c.is_ascii_digit()) {
        return Err(format!("invalid amount '{amount}': fractional part must be 0-8 digits"));
    }
    let mut padded = String::with_capacity(int_part.len() + 8);
    padded.push_str(int_part);
    padded.push_str(frac_part);
    for _ in frac_part.len()..8 {
        padded.push('0');
    }
    padded.parse::<u64>().map_err(|e| format!("invalid amount '{amount}': {e}"))
}

/// Mirrors Go `utils.FormatKas` (8 decimal places, fixed 19-char
/// width, space-padded for zero amounts).
fn format_kas(amount_sompi: u64) -> String {
    if amount_sompi == 0 {
        return "                   ".to_owned();
    }
    let kas = amount_sompi as f64 / SOMPI_PER_KASPA as f64;
    format!("{kas:19.8}")
}

fn fee_policy_from_args(fee_rate: Option<f64>, max_fee_rate: Option<f64>, max_fee: Option<u64>) -> Option<FeePolicy> {
    if let Some(r) = fee_rate.filter(|v| *v > 0.0) {
        Some(FeePolicy { fee_policy: Some(fee_policy::FeePolicy::ExactFeeRate(r)) })
    } else if let Some(r) = max_fee_rate.filter(|v| *v > 0.0) {
        Some(FeePolicy { fee_policy: Some(fee_policy::FeePolicy::MaxFeeRate(r)) })
    } else {
        max_fee.filter(|v| *v > 0).map(|m| FeePolicy { fee_policy: Some(fee_policy::FeePolicy::MaxFee(m)) })
    }
}

async fn dial_daemon(addr: &str) -> Result<DaemonClient, String> {
    DaemonClient::dial(addr).await.map_err(|e| format!("{e}"))
}

fn with_timeout<T>(req: T) -> Request<T> {
    let mut r = Request::new(req);
    r.set_timeout(DAEMON_TIMEOUT);
    r
}

fn xpub_prefix(network: &NetworkFlags) -> Bip32Prefix {
    // Go uses `kpub`/`ktub` per network at the keyfile-write boundary
    // (see `cmd/kaspawallet/libkaspawallet/bip39.go`'s extended-key
    // version selection).
    match network_type(network) {
        NetworkType::Mainnet => Bip32Prefix::KPUB,
        NetworkType::Testnet | NetworkType::Simnet | NetworkType::Devnet => Bip32Prefix::KTUB,
    }
}

fn network_type(network: &NetworkFlags) -> NetworkType {
    if network.simnet {
        NetworkType::Simnet
    } else if network.devnet {
        NetworkType::Devnet
    } else if network.testnet {
        NetworkType::Testnet
    } else {
        NetworkType::Mainnet
    }
}

fn master_xpub_from_mnemonic(mnemonic_phrase: &str, is_multisig: bool, prefix: Bip32Prefix) -> Result<String, String> {
    let mnemonic = Mnemonic::new(mnemonic_phrase, Language::English).map_err(|e| format!("invalid mnemonic: {e}"))?;
    let seed = mnemonic.to_seed("");
    let master = ExtendedPrivateKey::<SecretKey>::new(seed.as_bytes()).map_err(|e| format!("master xpriv derivation: {e}"))?;
    let purpose = if is_multisig { MULTISIG_PURPOSE } else { SINGLE_SIGNER_PURPOSE };
    let path = DerivationPath::from_str(&format!("m/{purpose}'/{COIN_TYPE}'/0'")).map_err(|e| format!("derivation path: {e}"))?;
    let cosigner = master.derive_path(&path).map_err(|e| format!("cosigner derivation: {e}"))?;
    let xpub: ExtendedPublicKey<secp256k1::PublicKey> = (&cosigner).into();
    Ok(xpub.to_string(Some(prefix)))
}

// ---- daemon-client subcommands -------------------------------------

pub fn run_balance(args: BalanceArgs, top: &NetworkFlags) -> ExitCode {
    let _network = merge_network(top, &args.network);
    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        let resp = match client.inner_mut().get_balance(with_timeout(GetBalanceRequest {})).await {
            Ok(r) => r.into_inner(),
            Err(s) => return fail(format!("GetBalance failed: {s}")),
        };
        let pending_suffix = if !args.verbose && resp.pending > 0 { " (pending)" } else { "" };
        if args.verbose {
            println!("Address                                                                       Available             Pending");
            println!("-----------------------------------------------------------------------------------------------------------");
            for entry in &resp.address_balances {
                println!("{} {} {}", entry.address, format_kas(entry.available), format_kas(entry.pending));
            }
            println!("-----------------------------------------------------------------------------------------------------------");
            print!("                                                 ");
        }
        println!("Total balance, KAS {} {}{}", format_kas(resp.available), format_kas(resp.pending), pending_suffix);
        ExitCode::SUCCESS
    })
}

pub fn run_new_address(args: NewAddressArgs, top: &NetworkFlags) -> ExitCode {
    let _network = merge_network(top, &args.network);
    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        let resp = match client.inner_mut().new_address(with_timeout(NewAddressRequest {})).await {
            Ok(r) => r.into_inner(),
            Err(s) => return fail(format!("NewAddress failed: {s}")),
        };
        println!("New address:\n{}", resp.address);
        ExitCode::SUCCESS
    })
}

pub fn run_show_addresses(args: ShowAddressesArgs, top: &NetworkFlags) -> ExitCode {
    let _network = merge_network(top, &args.network);
    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        let resp = match client.inner_mut().show_addresses(with_timeout(ShowAddressesRequest {})).await {
            Ok(r) => r.into_inner(),
            Err(s) => return fail(format!("ShowAddresses failed: {s}")),
        };
        println!("Addresses ({}):", resp.address.len());
        for addr in &resp.address {
            println!("{addr}");
        }
        println!(
            "\nNote: the above are only addresses that were manually created by the 'new-address' command. \
If you want to see a list of all addresses, including change addresses, that have a positive balance, use the command 'balance -v'"
        );
        ExitCode::SUCCESS
    })
}

pub fn run_broadcast(args: BroadcastArgs, top: &NetworkFlags) -> ExitCode {
    let _network = merge_network(top, &args.network);
    let tx_hex = match resolve_transaction_hex(args.transaction.as_deref(), args.transaction_file.as_deref(), "broadcast") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let transactions = match decode_transactions_from_hex(&tx_hex) {
        Ok(t) => t,
        Err(e) => return fail(format!("'broadcast': invalid hex: {e}")),
    };
    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        let resp = match client.inner_mut().broadcast(with_timeout(BroadcastRequest { is_domain: false, transactions })).await {
            Ok(r) => r.into_inner(),
            Err(s) => return fail(format!("Broadcast failed: {s}")),
        };
        println!("Transactions were sent successfully");
        println!("Transaction ID(s): ");
        for txid in &resp.tx_i_ds {
            println!("\t{txid}");
        }
        ExitCode::SUCCESS
    })
}

pub fn run_broadcast_replacement(args: BroadcastArgs, top: &NetworkFlags) -> ExitCode {
    let _network = merge_network(top, &args.network);
    let tx_hex = match resolve_transaction_hex(args.transaction.as_deref(), args.transaction_file.as_deref(), "broadcast-replacement")
    {
        Ok(s) => s,
        Err(e) => return e,
    };
    let transactions = match decode_transactions_from_hex(&tx_hex) {
        Ok(t) => t,
        Err(e) => return fail(format!("'broadcast-replacement': invalid hex: {e}")),
    };
    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        let resp =
            match client.inner_mut().broadcast_replacement(with_timeout(BroadcastRequest { is_domain: false, transactions })).await {
                Ok(r) => r.into_inner(),
                Err(s) => return fail(format!("BroadcastReplacement failed: {s}")),
            };
        println!("Transactions were sent successfully");
        println!("Transaction ID(s): ");
        for txid in &resp.tx_i_ds {
            println!("\t{txid}");
        }
        ExitCode::SUCCESS
    })
}

pub fn run_bump_fee(args: BumpFeeArgs, top: &NetworkFlags) -> ExitCode {
    let network = merge_network(top, &args.network);
    let password = match require_password(&args.password, "bump-fee") {
        Ok(p) => p,
        Err(e) => return e,
    };
    let (kf, _path) = match read_keyfile(&network, args.keys_file.as_deref()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if kf.extended_public_keys.len() > kf.encrypted_mnemonics.len() {
        return fail("cannot use 'bump-fee' command for multisig wallet without all of the keys");
    }
    let policy = fee_policy_from_args(args.fee_rate, args.max_fee_rate, args.max_fee);

    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        // Mirror Go: the BumpFee request omits the password. The
        // daemon returns unsigned replacement transactions; signing
        // happens client-side and broadcast uses the replacement
        // RPC.
        let req = BumpFeeRequest {
            password: String::new(),
            from: args.from_address.clone(),
            use_existing_change_address: args.use_existing_change_address,
            fee_policy: policy,
            tx_id: args.txid.clone().unwrap_or_default(),
        };
        let unsigned = match client.inner_mut().bump_fee(with_timeout(req)).await {
            Ok(r) => r.into_inner().transactions,
            Err(s) => return fail(format!("BumpFee failed: {s}")),
        };
        let mnemonics = match keyfile::decrypt_mnemonics(&kf, password.as_bytes()) {
            Ok(m) => m,
            Err(e) => return fail(format!("keyfile decryption failed: {e}")),
        };
        let mut signed: Vec<Vec<u8>> = Vec::with_capacity(unsigned.len());
        for bytes in &unsigned {
            let mut pst = match serialization::deserialize_partially_signed_transaction(bytes) {
                Ok(p) => p,
                Err(e) => return fail(format!("PSTX deserialization failed: {e}")),
            };
            for mnemonic in mnemonics.iter() {
                let res = if kf.ecdsa {
                    sign_pst_ecdsa_with_mnemonic(&mut pst, mnemonic, "")
                } else {
                    sign_pst_schnorr_with_mnemonic(&mut pst, mnemonic, "")
                };
                if let Err(e) = res {
                    return fail(format!("sign failed: {e}"));
                }
            }
            let out = match serialization::serialize_partially_signed_transaction(&pst) {
                Ok(b) => b,
                Err(e) => return fail(format!("PSTX serialization failed: {e}")),
            };
            signed.push(out);
        }

        println!("Broadcasting {} transaction(s)", signed.len());
        let chunk_size = 100;
        let total = signed.len();
        let mut sent = 0usize;
        for chunk in signed.chunks(chunk_size) {
            let resp = match client
                .inner_mut()
                .broadcast_replacement(with_timeout(BroadcastRequest { is_domain: false, transactions: chunk.to_vec() }))
                .await
            {
                Ok(r) => r.into_inner(),
                Err(s) => return fail(format!("BroadcastReplacement failed: {s}")),
            };
            sent += chunk.len();
            let pct = 100.0 * sent as f64 / total as f64;
            println!("Broadcasted {} transaction(s) (broadcasted {pct:.2}% of the transactions so far)", chunk.len());
            println!("Broadcasted Transaction ID(s): ");
            for txid in &resp.tx_i_ds {
                println!("\t{txid}");
            }
        }
        if args.show_serialized {
            println!("Serialized Transaction(s) (can be parsed via the `parse` command or resent via `broadcast`): ");
            for tx in &signed {
                println!("\t{}\n", hex::encode(tx));
            }
        }
        ExitCode::SUCCESS
    })
}

pub fn run_bump_fee_unsigned(args: BumpFeeUnsignedArgs, top: &NetworkFlags) -> ExitCode {
    let _network = merge_network(top, &args.network);
    let policy = fee_policy_from_args(args.fee_rate, args.max_fee_rate, args.max_fee);

    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        let req = BumpFeeRequest {
            password: String::new(),
            from: args.from_address.clone(),
            use_existing_change_address: args.use_existing_change_address,
            fee_policy: policy,
            tx_id: args.txid.clone().unwrap_or_default(),
        };
        let resp = match client.inner_mut().bump_fee(with_timeout(req)).await {
            Ok(r) => r.into_inner(),
            Err(s) => return fail(format!("BumpFee failed: {s}")),
        };
        eprintln!("Created unsigned transaction");
        println!("{}", encode_transactions_to_hex(&resp.transactions));
        ExitCode::SUCCESS
    })
}

pub fn run_get_daemon_version(args: GetDaemonVersionArgs) -> ExitCode {
    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        match client.get_version().await {
            Ok(v) => {
                println!("{v}");
                ExitCode::SUCCESS
            }
            Err(s) => fail(format!("GetVersion failed: {s}")),
        }
    })
}

pub fn run_create_unsigned_transaction(args: CreateUnsignedTransactionArgs, top: &NetworkFlags) -> ExitCode {
    let _network = merge_network(top, &args.network);

    let send_amount_sompi = if args.send_all {
        0
    } else {
        match args.send_amount.as_deref() {
            Some(s) => match parse_kas_to_sompi(s) {
                Ok(v) => v,
                Err(e) => return fail(format!("'create-unsigned-transaction': {e}")),
            },
            None => return fail("'create-unsigned-transaction': either --send-amount or --send-all is required"),
        }
    };
    let policy = fee_policy_from_args(args.fee_rate, args.max_fee_rate, args.max_fee);

    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        let req = CreateUnsignedTransactionsRequest {
            address: args.to_address.clone(),
            amount: send_amount_sompi,
            from: args.from_address.clone(),
            use_existing_change_address: args.use_existing_change_address,
            is_send_all: args.send_all,
            fee_policy: policy,
        };
        let resp = match client.inner_mut().create_unsigned_transactions(with_timeout(req)).await {
            Ok(r) => r.into_inner(),
            Err(s) => return fail(format!("CreateUnsignedTransactions failed: {s}")),
        };
        eprintln!("Created unsigned transaction");
        println!("{}", encode_transactions_to_hex(&resp.unsigned_transactions));
        ExitCode::SUCCESS
    })
}

pub fn run_send(args: SendArgs, top: &NetworkFlags) -> ExitCode {
    let _network = merge_network(top, &args.network);
    let password = match require_password(&args.password, "send") {
        Ok(p) => p,
        Err(e) => return e,
    };
    let network = merge_network(top, &args.network);
    let (kf, _path) = match read_keyfile(&network, args.keys_file.as_deref()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    if kf.extended_public_keys.len() > kf.encrypted_mnemonics.len() {
        return fail("cannot use 'send' command for multisig wallet without all of the keys");
    }
    let send_amount_sompi = if args.send_all {
        0
    } else {
        match args.send_amount.as_deref() {
            Some(s) => match parse_kas_to_sompi(s) {
                Ok(v) => v,
                Err(e) => return fail(format!("'send': {e}")),
            },
            None => return fail("'send': either --send-amount or --send-all is required"),
        }
    };
    let policy = fee_policy_from_args(args.fee_rate, args.max_fee_rate, args.max_fee);

    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        let req = CreateUnsignedTransactionsRequest {
            address: args.to_address.clone(),
            amount: send_amount_sompi,
            from: args.from_address.clone(),
            use_existing_change_address: args.use_existing_change_address,
            is_send_all: args.send_all,
            fee_policy: policy,
        };
        let unsigned = match client.inner_mut().create_unsigned_transactions(with_timeout(req)).await {
            Ok(r) => r.into_inner().unsigned_transactions,
            Err(s) => return fail(format!("CreateUnsignedTransactions failed: {s}")),
        };
        let mnemonics = match keyfile::decrypt_mnemonics(&kf, password.as_bytes()) {
            Ok(m) => m,
            Err(e) => return fail(format!("keyfile decryption failed: {e}")),
        };
        let mut signed: Vec<Vec<u8>> = Vec::with_capacity(unsigned.len());
        for bytes in &unsigned {
            let mut pst = match serialization::deserialize_partially_signed_transaction(bytes) {
                Ok(p) => p,
                Err(e) => return fail(format!("PSTX deserialization failed: {e}")),
            };
            for mnemonic in mnemonics.iter() {
                let res = if kf.ecdsa {
                    sign_pst_ecdsa_with_mnemonic(&mut pst, mnemonic, "")
                } else {
                    sign_pst_schnorr_with_mnemonic(&mut pst, mnemonic, "")
                };
                if let Err(e) = res {
                    return fail(format!("sign failed: {e}"));
                }
            }
            let out = match serialization::serialize_partially_signed_transaction(&pst) {
                Ok(b) => b,
                Err(e) => return fail(format!("PSTX serialization failed: {e}")),
            };
            signed.push(out);
        }

        println!("Broadcasting {} transaction(s)", signed.len());
        // Reset timeout for broadcast (matches Go's separate context).
        let chunk_size = 100;
        let total = signed.len();
        let mut sent = 0usize;
        for chunk in signed.chunks(chunk_size) {
            let resp = match client
                .inner_mut()
                .broadcast(with_timeout(BroadcastRequest { is_domain: false, transactions: chunk.to_vec() }))
                .await
            {
                Ok(r) => r.into_inner(),
                Err(s) => return fail(format!("Broadcast failed: {s}")),
            };
            sent += chunk.len();
            let pct = 100.0 * sent as f64 / total as f64;
            println!("Broadcasted {} transaction(s) (broadcasted {pct:.2}% of the transactions so far)", chunk.len());
            println!("Broadcasted Transaction ID(s): ");
            for txid in &resp.tx_i_ds {
                println!("\t{txid}");
            }
        }
        // `--show-serialized` (Go names it differently in client vs
        // daemon; matches the `verbose` field on the Go config struct
        // for the `send` subcommand).
        if args.show_serialized {
            println!("Serialized Transaction(s) (can be parsed via the `parse` command or resent via `broadcast`): ");
            for tx in &signed {
                println!("\t{}\n", hex::encode(tx));
            }
        }
        ExitCode::SUCCESS
    })
}

// ---- offline subcommands -------------------------------------------

pub fn run_sign(args: SignArgs, top: &NetworkFlags) -> ExitCode {
    if let Err(e) = require_backend_available(args.wallet_backend) {
        return e;
    }
    let tx_hex = match resolve_transaction_hex(args.transaction.as_deref(), args.transaction_file.as_deref(), "sign") {
        Ok(s) => s,
        Err(e) => return e,
    };
    let password = match require_password(&args.password, "sign") {
        Ok(p) => p,
        Err(e) => return e,
    };
    let network = merge_network(top, &args.network);
    let (kf, _path) = match read_keyfile(&network, args.keys_file.as_deref()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mnemonics = match keyfile::decrypt_mnemonics(&kf, password.as_bytes()) {
        Ok(m) => m,
        Err(e) => return fail(format!("keyfile decryption failed: {e}")),
    };
    let partially_signed = match decode_transactions_from_hex(&tx_hex) {
        Ok(t) => t,
        Err(e) => return fail(format!("'sign': invalid hex: {e}")),
    };
    let mut updated: Vec<Vec<u8>> = Vec::with_capacity(partially_signed.len());
    let mut all_fully_signed = true;
    for bytes in &partially_signed {
        let mut pst = match serialization::deserialize_partially_signed_transaction(bytes) {
            Ok(p) => p,
            Err(e) => return fail(format!("PSTX deserialization failed: {e}")),
        };
        for mnemonic in mnemonics.iter() {
            let res = if kf.ecdsa {
                sign_pst_ecdsa_with_mnemonic(&mut pst, mnemonic, "")
            } else {
                sign_pst_schnorr_with_mnemonic(&mut pst, mnemonic, "")
            };
            if let Err(e) = res {
                return fail(format!("sign failed: {e}"));
            }
        }
        if !is_pst_fully_signed(&pst) {
            all_fully_signed = false;
        }
        let out = match serialization::serialize_partially_signed_transaction(&pst) {
            Ok(b) => b,
            Err(e) => return fail(format!("PSTX serialization failed: {e}")),
        };
        updated.push(out);
    }
    if all_fully_signed {
        eprintln!("The transaction is signed and ready to broadcast");
    } else {
        eprintln!("Successfully signed transaction");
    }
    println!("{}", encode_transactions_to_hex(&updated));
    ExitCode::SUCCESS
}

pub fn run_dump_unencrypted_data(args: DumpUnencryptedDataArgs, top: &NetworkFlags) -> ExitCode {
    if let Err(e) = require_backend_available(args.wallet_backend) {
        return e;
    }
    if !args.yes {
        return fail(
            "'dump-unencrypted-data' requires --yes to confirm (interactive y/N prompt is a Phase-2 enhancement of the Rust port)",
        );
    }
    let password = match require_password(&args.password, "dump-unencrypted-data") {
        Ok(p) => p,
        Err(e) => return e,
    };
    let network = merge_network(top, &args.network);
    let (kf, _path) = match read_keyfile(&network, args.keys_file.as_deref()) {
        Ok(v) => v,
        Err(e) => return e,
    };
    let mnemonics = match keyfile::decrypt_mnemonics(&kf, password.as_bytes()) {
        Ok(m) => m,
        Err(e) => return fail(format!("keyfile decryption failed: {e}")),
    };
    let is_multisig = kf.extended_public_keys.len() > 1;
    let prefix = xpub_prefix(&network);
    let mut mnemonic_xpubs: Vec<String> = Vec::with_capacity(mnemonics.len());
    for (i, m) in mnemonics.iter().enumerate() {
        println!("Mnemonic #{}:\n{m}\n", i + 1);
        match master_xpub_from_mnemonic(m, is_multisig, prefix) {
            Ok(x) => mnemonic_xpubs.push(x),
            Err(e) => return fail(format!("xpub derivation: {e}")),
        }
    }
    let mut i = 1;
    for xpub in &kf.extended_public_keys {
        if mnemonic_xpubs.iter().any(|own| own == xpub) {
            continue;
        }
        println!("Extended Public key #{i}:\n{xpub}\n");
        i += 1;
    }
    println!("Minimum number of signatures: {}", kf.minimum_signatures);
    ExitCode::SUCCESS
}

pub fn run_create(args: CreateArgs, top: &NetworkFlags) -> ExitCode {
    if let Err(e) = require_backend_available(args.wallet_backend) {
        return e;
    }
    if args.import {
        return fail(
            "'create --import' (interactive mnemonic import) is a Phase-2 enhancement of the Rust port; use --keys-file with a pre-existing Go-format keyfile in the interim",
        );
    }
    if args.num_public_keys > args.num_private_keys {
        return fail(
            "'create' with cosigner xpub stdin prompts (--num-public-keys > --num-private-keys) is a Phase-2 enhancement of the Rust port; multisig wallet creation requires interactive stdin",
        );
    }
    if args.num_private_keys != args.num_public_keys {
        return fail("'create': --num-private-keys and --num-public-keys must match in non-import mode");
    }
    let password = match require_password(&args.password, "create") {
        Ok(p) => p,
        Err(e) => return e,
    };
    let network = merge_network(top, &args.network);
    let prefix = xpub_prefix(&network);
    let is_multisig = args.num_public_keys > 1;

    let resolved_path = match args.keys_file.as_deref() {
        Some(p) => PathBuf::from(p),
        None => match default_keys_file(network.network_name()) {
            Ok(p) => p,
            Err(e) => return fail(format!("default keyfile path resolution failed: {e}")),
        },
    };
    if resolved_path.exists() && !args.yes {
        return fail(format!(
            "keyfile '{}' already exists; pass --yes to overwrite (interactive overwrite prompt is a Phase-2 enhancement of the Rust port)",
            resolved_path.display()
        ));
    }

    let mut encrypted: Vec<keyfile::EncryptedMnemonic> = Vec::with_capacity(args.num_private_keys as usize);
    let mut xpubs: Vec<String> = Vec::with_capacity(args.num_private_keys as usize);
    for i in 0..args.num_private_keys as usize {
        let mnemonic = match Mnemonic::random(WordCount::Words24, Language::English) {
            Ok(m) => m,
            Err(e) => return fail(format!("mnemonic generation: {e}")),
        };
        let phrase = mnemonic.phrase().to_owned();
        let xpub = match master_xpub_from_mnemonic(&phrase, is_multisig, prefix) {
            Ok(x) => x,
            Err(e) => return fail(format!("xpub derivation: {e}")),
        };
        let record = match keyfile::encrypt_mnemonic(&phrase, password.as_bytes()) {
            Ok(r) => r,
            Err(e) => return fail(format!("mnemonic encryption: {e}")),
        };
        println!("Extended public key of mnemonic #{}:\n{xpub}\n", i + 1);
        xpubs.push(xpub);
        encrypted.push(record);
    }
    println!(
        "Notice the above is neither a secret key to your wallet (use \"kaspawallet dump-unencrypted-data\" to see a secret seed phrase) \
nor a wallet public address (use \"kaspawallet new-address\" to create and see one)\n"
    );

    let kf = KeysFile {
        version: LATEST_VERSION,
        num_threads: 0,
        encrypted_mnemonics: encrypted,
        extended_public_keys: xpubs,
        minimum_signatures: args.min_signatures,
        cosigner_index: 0,
        last_used_external_index: 0,
        last_used_internal_index: 0,
        ecdsa: args.ecdsa,
    };

    if let Some(parent) = resolved_path.parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        return fail(format!("failed to create keyfile parent '{}': {e}", parent.display()));
    }
    if let Err(e) = keyfile::save_to_path(&kf, &resolved_path) {
        return fail(format!("save keyfile '{}': {e}", resolved_path.display()));
    }
    println!("Wrote the keys into {}", resolved_path.display());
    ExitCode::SUCCESS
}

pub fn run_sweep(args: SweepArgs, top: &NetworkFlags) -> ExitCode {
    if let Err(e) = require_backend_available(args.wallet_backend) {
        return e;
    }
    let network = merge_network(top, &args.network);
    let pk_hex = match args.private_key.as_deref() {
        Some(s) if !s.is_empty() => s,
        _ => return fail("'sweep' requires --private-key (hex-encoded 32-byte secp256k1 private key)"),
    };
    let pk_bytes = match hex::decode(pk_hex) {
        Ok(b) => b,
        Err(e) => return fail(format!("'sweep': --private-key hex decode failed: {e}")),
    };
    if pk_bytes.len() != 32 {
        return fail(format!("'sweep': --private-key must be 32 bytes (got {} bytes)", pk_bytes.len()));
    }
    let secret = match secp256k1::SecretKey::from_slice(pk_bytes.as_slice()) {
        Ok(s) => s,
        Err(e) => return fail(format!("'sweep': invalid secp256k1 private key: {e}")),
    };
    let secp = secp256k1::SECP256K1;
    let (xonly, _parity) = secp256k1::Keypair::from_secret_key(secp, &secret).x_only_public_key();
    let xonly_bytes = xonly.serialize();
    let addr = kaspa_addresses::Address::new(network.address_prefix(), kaspa_addresses::Version::PubKey, &xonly_bytes);

    // The full sweep flow requires querying the daemon for the
    // sweep-source address's UTXOs, building one or more sweep
    // transactions whose recipient is a daemon-generated wallet
    // address, signing the inputs with the supplied private key,
    // and broadcasting them. The daemon-side
    // `GetExternalSpendableUTXOs` + `NewAddress` + `Broadcast`
    // primitives are wired (B4-tx-composition / B4-tx-mechanical);
    // the sweep transaction builder (consensus-tx construction
    // from raw private-key inputs, distinct from the
    // libkaspawallet PSTX flow used by `sign`) is a Phase-2
    // surface the standalone CLI does not yet compose. The
    // operator-visible diagnostic surfaces the daemon-known UTXO
    // count and the resolved sweep-source address so a manual
    // sweep can be constructed and broadcast via the daemon-client
    // surface in the interim.

    let runtime = match build_runtime() {
        Ok(r) => r,
        Err(e) => return e,
    };
    runtime.block_on(async move {
        let mut client = match dial_daemon(&args.daemon_address).await {
            Ok(c) => c,
            Err(e) => return fail(format!("dial daemon '{}': {e}", args.daemon_address)),
        };
        let resp = match client
            .inner_mut()
            .get_external_spendable_utx_os(with_timeout(GetExternalSpendableUtxOsRequest { address: addr.to_string() }))
            .await
        {
            Ok(r) => r.into_inner(),
            Err(s) => return fail(format!("GetExternalSpendableUTXOs failed: {s}")),
        };
        let total: u64 = resp.entries.iter().filter_map(|e| e.utxo_entry.as_ref().map(|u| u.amount)).sum();
        eprintln!(
            "Sweep source address: {addr}\nDaemon-known spendable UTXOs: {} (total {} sompi, per-input fee {SWEEP_FEE_PER_INPUT} sompi)",
            resp.entries.len(),
            total
        );
        eprintln!(
            "Building the sweep transaction batch from raw private-key inputs is a Phase-2 enhancement of the Rust standalone CLI; use the daemon-client \
'send' subcommand once the source address is funded into the daemon's wallet, or compose a sweep manually via the daemon's `Broadcast` RPC. Tracked separately."
        );
        ExitCode::from(2)
    })
}
