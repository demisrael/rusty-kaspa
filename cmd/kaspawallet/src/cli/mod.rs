//! Command-line surface for the grandpa wallet binary. The
//! 17-subcommand registry mirrors the Go reference at
//! `https://github.com/kaspanet/kaspad/blob/master/cmd/kaspawallet/config.go`
//! (`config.go` `parseCommandLine`). Long names, short flags,
//! defaults, and `required` dispositions are copied from the Go
//! `go-flags` struct tags.

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
