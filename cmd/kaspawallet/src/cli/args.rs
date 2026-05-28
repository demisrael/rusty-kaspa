//! Clap derive surface. Subcommand names, long flags, short
//! flags, defaults, and `required` dispositions describe the
//! observable wallet CLI.

use clap::{Parser, Subcommand as ClapSubcommand};

use super::network::NetworkFlags;
use super::wallet_backend::WalletBackend;

/// Default daemon listen address. Loopback-only binding is the
/// shipped behaviour.
pub const DEFAULT_LISTEN: &str = "localhost:8082";

/// Default RPC server target.
pub const DEFAULT_RPC_SERVER: &str = "localhost";

/// Default daemon wait-timeout in seconds.
pub const DEFAULT_WAIT_TIMEOUT_SEC: u32 = 30;

/// Default minimum-signatures for `create`.
pub const DEFAULT_MIN_SIGNATURES: u32 = 1;

/// Default number of private keys for `create`.
pub const DEFAULT_NUM_PRIVATE_KEYS: u32 = 1;

/// Default total number of keys for `create`.
pub const DEFAULT_NUM_PUBLIC_KEYS: u32 = 1;

/// Top-level CLI surface.
#[derive(Parser, Debug)]
#[command(name = "kaspawallet", version, about = "Subcommand-style Kaspa wallet binary.")]
#[command(disable_help_subcommand = true)]
pub struct Cli {
    /// Network flags accepted at the top level as well as on every
    /// subcommand; per-subcommand values merge with the top-level
    /// value via [`NetworkFlags::combine`].
    #[command(flatten)]
    pub network: NetworkFlags,

    #[command(subcommand)]
    pub command: Subcommand,
}

#[derive(ClapSubcommand, Debug)]
pub enum Subcommand {
    /// Create a new wallet keyfile.
    Create(CreateArgs),
    /// Print the unencrypted wallet data (mnemonic and extended
    /// keys). Use only on a trusted environment.
    DumpUnencryptedData(DumpUnencryptedDataArgs),
    /// Start the wallet daemon.
    StartDaemon(StartDaemonArgs),
    /// Show the balance held by the wallet's addresses.
    Balance(BalanceArgs),
    /// Construct, sign, and broadcast a transaction.
    Send(SendArgs),
    /// Construct an unsigned transaction.
    CreateUnsignedTransaction(CreateUnsignedTransactionArgs),
    /// Sign one or more unsigned transactions with a keyfile's
    /// private keys.
    Sign(SignArgs),
    /// Broadcast a signed transaction over the running daemon.
    Broadcast(BroadcastArgs),
    /// Parse a transaction hex and print its contents.
    Parse(ParseArgs),
    /// Show every address the daemon's wallet has generated.
    ShowAddresses(ShowAddressesArgs),
    /// Generate a new external receiving address.
    NewAddress(NewAddressArgs),
    /// Print the binary's semantic version.
    Version(VersionArgs),
    /// Sweep all funds controlled by the supplied private key
    /// into the running daemon's wallet.
    Sweep(SweepArgs),
    /// Broadcast a signed replacement transaction (RBF) over the
    /// running daemon. Same flags as `broadcast`; the daemon
    /// forwards via `kaspad`'s replacement-aware submit RPC.
    BroadcastReplacement(BroadcastArgs),
    /// Bump the fee of a pending mempool transaction. Constructs
    /// a higher-fee replacement, signs it locally with the
    /// keyfile, and broadcasts via the daemon.
    BumpFee(BumpFeeArgs),
    /// Bump the fee of a pending mempool transaction without
    /// signing. Emits the unsigned replacement transaction(s) as
    /// hex for offline signing.
    BumpFeeUnsigned(BumpFeeUnsignedArgs),
    /// Print the running daemon's reported version string.
    GetDaemonVersion(GetDaemonVersionArgs),
}

/// `create` subcommand arguments.
#[derive(clap::Args, Debug)]
pub struct CreateArgs {
    /// Keyfile location.
    #[arg(long = "keys-file", short = 'f', value_name = "PATH")]
    pub keys_file: Option<String>,

    /// Wallet password.
    #[arg(long, short = 'p', value_name = "PASSWORD")]
    pub password: Option<String>,

    /// Assume yes to all interactive prompts.
    #[arg(long, short = 'y')]
    pub yes: bool,

    /// Minimum required signatures (multisig threshold).
    #[arg(long = "min-signatures", short = 'm', default_value_t = DEFAULT_MIN_SIGNATURES)]
    pub min_signatures: u32,

    /// Number of locally-held private keys.
    #[arg(long = "num-private-keys", short = 'k', default_value_t = DEFAULT_NUM_PRIVATE_KEYS)]
    pub num_private_keys: u32,

    /// Total number of public keys (cosigners).
    #[arg(long = "num-public-keys", short = 'n', default_value_t = DEFAULT_NUM_PUBLIC_KEYS)]
    pub num_public_keys: u32,

    /// Create an ECDSA wallet instead of the default Schnorr.
    #[arg(long)]
    pub ecdsa: bool,

    /// Import existing private keys instead of generating new ones.
    #[arg(long, short = 'i')]
    pub import: bool,

    /// Wallet backend.
    #[arg(long = "wallet-backend", short = 'W', value_enum, default_value_t = WalletBackend::default())]
    pub wallet_backend: WalletBackend,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `dump-unencrypted-data` subcommand arguments.
#[derive(clap::Args, Debug)]
pub struct DumpUnencryptedDataArgs {
    #[arg(long = "keys-file", short = 'f', value_name = "PATH")]
    pub keys_file: Option<String>,

    #[arg(long, short = 'p', value_name = "PASSWORD")]
    pub password: Option<String>,

    #[arg(long, short = 'y')]
    pub yes: bool,

    #[arg(long = "wallet-backend", short = 'W', value_enum, default_value_t = WalletBackend::default())]
    pub wallet_backend: WalletBackend,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `start-daemon` subcommand arguments.
#[derive(clap::Args, Debug)]
pub struct StartDaemonArgs {
    #[arg(long = "keys-file", short = 'f', value_name = "PATH")]
    pub keys_file: Option<String>,

    #[arg(long, short = 'p', value_name = "PASSWORD")]
    pub password: Option<String>,

    /// kaspad gRPC endpoint to connect to.
    #[arg(long = "rpcserver", short = 's', default_value = DEFAULT_RPC_SERVER, value_name = "HOST[:PORT]")]
    pub rpcserver: String,

    /// Daemon gRPC listen address. Default is loopback-only.
    #[arg(long, short = 'l', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub listen: String,

    /// Waiting timeout for RPC calls (seconds).
    #[arg(long = "wait-timeout", short = 'w', default_value_t = DEFAULT_WAIT_TIMEOUT_SEC, value_name = "SECONDS")]
    pub wait_timeout: u32,

    /// HTTP profiling listen port (1024..65535) for debug builds.
    #[arg(long, value_name = "PORT")]
    pub profile: Option<String>,

    #[arg(long = "wallet-backend", short = 'W', value_enum, default_value_t = WalletBackend::default())]
    pub wallet_backend: WalletBackend,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `balance` subcommand arguments. Daemon-client subcommands have
/// no `--wallet-backend` flag -- they inherit the backend the
/// daemon was bound to at `start-daemon` time.
#[derive(clap::Args, Debug)]
pub struct BalanceArgs {
    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,

    /// Verbose: show per-address balances.
    #[arg(long, short = 'v')]
    pub verbose: bool,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `send` subcommand arguments. `-v` here is `send-amount`, the
/// same short flag as `balance --verbose`; the two are on
/// different subcommands so there is no global conflict.
#[derive(clap::Args, Debug)]
pub struct SendArgs {
    #[arg(long = "keys-file", short = 'f', value_name = "PATH")]
    pub keys_file: Option<String>,

    #[arg(long, short = 'p', value_name = "PASSWORD")]
    pub password: Option<String>,

    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,

    /// Destination address.
    #[arg(long = "to-address", short = 't', required = true, value_name = "KASPA_ADDRESS")]
    pub to_address: String,

    /// Source address. Repeat to accept several.
    #[arg(long = "from-address", short = 'a', value_name = "KASPA_ADDRESS")]
    pub from_address: Vec<String>,

    /// Send amount in KAS (mutually exclusive with `--send-all`).
    #[arg(long = "send-amount", short = 'v', value_name = "AMOUNT_KAS")]
    pub send_amount: Option<String>,

    /// Send every available unit (mutually exclusive with
    /// `--send-amount`).
    #[arg(long = "send-all")]
    pub send_all: bool,

    /// Reuse an existing change address rather than minting a new
    /// one.
    #[arg(long = "use-existing-change-address", short = 'u')]
    pub use_existing_change_address: bool,

    /// Maximum fee rate in sompi/gram.
    #[arg(long = "max-fee-rate", short = 'm', value_name = "SOMPI_PER_GRAM")]
    pub max_fee_rate: Option<f64>,

    /// Override fee-rate estimate (sompi/gram).
    #[arg(long = "fee-rate", short = 'r', value_name = "SOMPI_PER_GRAM")]
    pub fee_rate: Option<f64>,

    /// Maximum total fee in sompi.
    #[arg(long = "max-fee", short = 'x', value_name = "SOMPI")]
    pub max_fee: Option<u64>,

    /// Show hex-encoded sent transactions.
    #[arg(long = "show-serialized", short = 's')]
    pub show_serialized: bool,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `create-unsigned-transaction` subcommand arguments.
#[derive(clap::Args, Debug)]
pub struct CreateUnsignedTransactionArgs {
    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,

    #[arg(long = "to-address", short = 't', required = true, value_name = "KASPA_ADDRESS")]
    pub to_address: String,

    #[arg(long = "from-address", short = 'a', value_name = "KASPA_ADDRESS")]
    pub from_address: Vec<String>,

    #[arg(long = "send-amount", short = 'v', value_name = "AMOUNT_KAS")]
    pub send_amount: Option<String>,

    #[arg(long = "send-all")]
    pub send_all: bool,

    #[arg(long = "use-existing-change-address", short = 'u')]
    pub use_existing_change_address: bool,

    #[arg(long = "max-fee-rate", short = 'm', value_name = "SOMPI_PER_GRAM")]
    pub max_fee_rate: Option<f64>,

    #[arg(long = "fee-rate", short = 'r', value_name = "SOMPI_PER_GRAM")]
    pub fee_rate: Option<f64>,

    #[arg(long = "max-fee", short = 'x', value_name = "SOMPI")]
    pub max_fee: Option<u64>,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `sign` subcommand arguments. Offline; reads the keyfile
/// directly.
#[derive(clap::Args, Debug)]
pub struct SignArgs {
    #[arg(long = "keys-file", short = 'f', value_name = "PATH")]
    pub keys_file: Option<String>,

    #[arg(long, short = 'p', value_name = "PASSWORD")]
    pub password: Option<String>,

    /// Unsigned transaction(s) as hex.
    #[arg(long, short = 't', value_name = "HEX")]
    pub transaction: Option<String>,

    /// File containing unsigned transaction(s) as hex.
    #[arg(long = "transaction-file", short = 'F', value_name = "PATH")]
    pub transaction_file: Option<String>,

    #[arg(long = "wallet-backend", short = 'W', value_enum, default_value_t = WalletBackend::default())]
    pub wallet_backend: WalletBackend,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `broadcast` subcommand arguments.
#[derive(clap::Args, Debug)]
pub struct BroadcastArgs {
    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,

    #[arg(long, short = 't', value_name = "HEX")]
    pub transaction: Option<String>,

    #[arg(long = "transaction-file", short = 'F', value_name = "PATH")]
    pub transaction_file: Option<String>,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `parse` subcommand arguments. Offline; the `--keys-file` arg
/// is optional and enables address-ownership annotation.
#[derive(clap::Args, Debug)]
pub struct ParseArgs {
    #[arg(long = "keys-file", short = 'f', value_name = "PATH")]
    pub keys_file: Option<String>,

    #[arg(long, short = 't', value_name = "HEX")]
    pub transaction: Option<String>,

    #[arg(long = "transaction-file", short = 'F', value_name = "PATH")]
    pub transaction_file: Option<String>,

    /// Verbose: show transaction inputs.
    #[arg(long, short = 'v')]
    pub verbose: bool,

    #[arg(long = "wallet-backend", short = 'W', value_enum, default_value_t = WalletBackend::default())]
    pub wallet_backend: WalletBackend,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `show-addresses` subcommand arguments.
#[derive(clap::Args, Debug)]
pub struct ShowAddressesArgs {
    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `new-address` subcommand arguments.
#[derive(clap::Args, Debug)]
pub struct NewAddressArgs {
    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `version` subcommand arguments (no flags).
#[derive(clap::Args, Debug)]
pub struct VersionArgs {}

/// `sweep` subcommand arguments.
#[derive(clap::Args, Debug)]
pub struct SweepArgs {
    /// Hex-encoded private key.
    #[arg(long = "private-key", short = 'k', value_name = "HEX")]
    pub private_key: Option<String>,

    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,

    #[arg(long = "wallet-backend", short = 'W', value_enum, default_value_t = WalletBackend::default())]
    pub wallet_backend: WalletBackend,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `bump-fee` subcommand arguments. Local-signing flow: the
/// daemon returns unsigned replacement transactions, the CLI
/// signs them client-side, then broadcasts.
#[derive(clap::Args, Debug)]
pub struct BumpFeeArgs {
    /// Transaction ID of the pending mempool entry to replace.
    #[arg(long = "txid", short = 'i', value_name = "TXID")]
    pub txid: Option<String>,

    #[arg(long = "keys-file", short = 'f', value_name = "PATH")]
    pub keys_file: Option<String>,

    #[arg(long, short = 'p', value_name = "PASSWORD")]
    pub password: Option<String>,

    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,

    /// Restrict input selection to these source addresses. Repeat
    /// to accept several.
    #[arg(long = "from-address", short = 'a', value_name = "KASPA_ADDRESS")]
    pub from_address: Vec<String>,

    #[arg(long = "use-existing-change-address", short = 'u')]
    pub use_existing_change_address: bool,

    #[arg(long = "max-fee-rate", short = 'm', value_name = "SOMPI_PER_GRAM")]
    pub max_fee_rate: Option<f64>,

    #[arg(long = "fee-rate", short = 'r', value_name = "SOMPI_PER_GRAM")]
    pub fee_rate: Option<f64>,

    #[arg(long = "max-fee", short = 'x', value_name = "SOMPI")]
    pub max_fee: Option<u64>,

    /// Show hex-encoded signed replacement transactions after
    /// broadcast.
    #[arg(long = "show-serialized", short = 's')]
    pub show_serialized: bool,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `bump-fee-unsigned` subcommand arguments. Returns the daemon's
/// unsigned replacement transaction(s) as hex; no keyfile is
/// read.
#[derive(clap::Args, Debug)]
pub struct BumpFeeUnsignedArgs {
    /// Transaction ID of the pending mempool entry to replace.
    #[arg(long = "txid", short = 'i', value_name = "TXID")]
    pub txid: Option<String>,

    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,

    #[arg(long = "from-address", short = 'a', value_name = "KASPA_ADDRESS")]
    pub from_address: Vec<String>,

    #[arg(long = "use-existing-change-address", short = 'u')]
    pub use_existing_change_address: bool,

    #[arg(long = "max-fee-rate", short = 'm', value_name = "SOMPI_PER_GRAM")]
    pub max_fee_rate: Option<f64>,

    #[arg(long = "fee-rate", short = 'r', value_name = "SOMPI_PER_GRAM")]
    pub fee_rate: Option<f64>,

    #[arg(long = "max-fee", short = 'x', value_name = "SOMPI")]
    pub max_fee: Option<u64>,

    #[command(flatten)]
    pub network: NetworkFlags,
}

/// `get-daemon-version` subcommand arguments. Only
/// `--daemonaddress`; no network flags (the daemon's reported
/// version is network-agnostic).
#[derive(clap::Args, Debug)]
pub struct GetDaemonVersionArgs {
    #[arg(long = "daemonaddress", short = 'd', default_value = DEFAULT_LISTEN, value_name = "HOST:PORT")]
    pub daemon_address: String,
}
