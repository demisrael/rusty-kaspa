//! Command-line surface for the wallet binary: a 17-subcommand
//! registry with long names, short flags, defaults, and
//! `required` dispositions exposed via `clap`'s derive surface.

mod args;
mod network;
mod wallet_backend;

#[cfg(test)]
mod tests;

pub use args::{
    BalanceArgs, BroadcastArgs, BumpFeeArgs, BumpFeeUnsignedArgs, Cli, CreateArgs, CreateUnsignedTransactionArgs,
    DumpUnencryptedDataArgs, GetDaemonVersionArgs, NewAddressArgs, ParseArgs, SendArgs, ShowAddressesArgs, SignArgs, StartDaemonArgs,
    Subcommand, SweepArgs, VersionArgs,
};
pub use network::{NETWORK_FLAG_NAMES, NetworkFlags};
pub use wallet_backend::WalletBackend;
