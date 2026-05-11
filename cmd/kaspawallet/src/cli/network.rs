//! Network-flag group. Mirrors the Go reference's
//! `config.NetworkFlags` (`--testnet`, `--simnet`, `--devnet`,
//! `--override-dag-params-file`) at the per-subcommand level; the
//! Go binary embeds this group on every subcommand and merges with
//! any top-level value via `combineNetworkFlags`. Clap models the
//! group as a flattened struct with a mutually-exclusive arg group
//! covering the three boolean flags.

use clap::Args;

/// Canonical names of the network-flag long forms; the
/// subcommand-registry tests cross-check `clap`'s registered
/// long-flag set against this list to protect against silent
/// drift.
pub const NETWORK_FLAG_NAMES: &[&str] = &["testnet", "simnet", "devnet", "override-dag-params-file"];

#[derive(Args, Debug, Clone, Default)]
#[command(next_help_heading = "Network options")]
pub struct NetworkFlags {
    /// Use the test network.
    #[arg(long, group = "network")]
    pub testnet: bool,

    /// Use the simulation test network.
    #[arg(long, group = "network")]
    pub simnet: bool,

    /// Use the development test network.
    #[arg(long, group = "network")]
    pub devnet: bool,

    /// Overrides DAG params (allowed only on devnet).
    #[arg(long = "override-dag-params-file", value_name = "PATH")]
    pub override_dag_params_file: Option<String>,
}

impl NetworkFlags {
    /// Combine `self` with `other`, treating any truthy boolean on
    /// either side as truthy on the result. Mirrors the Go
    /// `combineNetworkFlags` function.
    pub fn combine(&mut self, other: &NetworkFlags) {
        self.testnet = self.testnet || other.testnet;
        self.simnet = self.simnet || other.simnet;
        self.devnet = self.devnet || other.devnet;
        if self.override_dag_params_file.is_none() {
            self.override_dag_params_file = other.override_dag_params_file.clone();
        }
    }

    /// Canonical kaspa address prefix used to encode addresses on
    /// the selected network. Mirrors Go's `dagconfig.Params.Prefix`.
    pub fn address_prefix(&self) -> kaspa_addresses::Prefix {
        if self.simnet {
            kaspa_addresses::Prefix::Simnet
        } else if self.devnet {
            kaspa_addresses::Prefix::Devnet
        } else if self.testnet {
            kaspa_addresses::Prefix::Testnet
        } else {
            kaspa_addresses::Prefix::Mainnet
        }
    }

    /// Canonical kaspa network-name string matching Go's
    /// `dagconfig.Params.Name` field. Used by the keyfile
    /// default-path resolver to mirror Go's
    /// `defaultKeysFile(netParams) =
    /// filepath.Join(defaultAppDir, netParams.Name, "keys.json")`.
    /// Source: https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/domain/dagconfig/params.go#L212
    /// (`MainnetParams.Name = "kaspa-mainnet"`); analogous lines for
    /// testnet-10 (`"kaspa-testnet-10"`), simnet (`"kaspa-simnet"`),
    /// devnet (`"kaspa-devnet"`).
    pub fn network_name(&self) -> &'static str {
        // Mutually-exclusive `clap` group means at most one of
        // simnet / devnet / testnet is set; mainnet is the default
        // when none is set. Phase 1 testnet target is testnet-10
        // (per task file's `KASPA_TN10_ENDPOINT` default), matching
        // Go `dagconfig.TestnetParams.Name`.
        if self.simnet {
            "kaspa-simnet"
        } else if self.devnet {
            "kaspa-devnet"
        } else if self.testnet {
            "kaspa-testnet-10"
        } else {
            "kaspa-mainnet"
        }
    }
}
