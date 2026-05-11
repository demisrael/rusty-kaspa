//! Wallet-backend selector flag. The default value is `go`
//! (legacy Go-kaspawallet keyfile, the only backend implemented in
//! this build); the other variants parse so that operator muscle
//! memory stays stable across future builds, but they error out
//! with a structured message at resolver time. Help-text wording
//! avoids any internal tracker identifier or session-time anchor
//! per the Mission source-text hygiene rule.

use clap::ValueEnum;

#[derive(ValueEnum, Clone, Copy, Debug, Default, PartialEq, Eq)]
#[clap(rename_all = "kebab-case")]
pub enum WalletBackend {
    /// Go-kaspawallet keyfile (default).
    #[default]
    Go,
    /// KDX 12-word seed wallet. Reserved value; not available in
    /// this build.
    Kdx,
    /// Tangem hardware wallet. Reserved value; not available in
    /// this build.
    Tangem,
    /// Ledger hardware wallet. Reserved value; not available in
    /// this build.
    Ledger,
    /// kaspa-ng wallet. Reserved value; not available in this
    /// build.
    KaspaNg,
}

impl WalletBackend {
    pub fn as_kebab(self) -> &'static str {
        match self {
            WalletBackend::Go => "go",
            WalletBackend::Kdx => "kdx",
            WalletBackend::Tangem => "tangem",
            WalletBackend::Ledger => "ledger",
            WalletBackend::KaspaNg => "kaspa-ng",
        }
    }

    /// True if this backend has a working `KeySource`
    /// implementation in the current build. Only `Go` qualifies in
    /// this build; the rest parse but resolve to an error.
    pub fn is_available(self) -> bool {
        matches!(self, WalletBackend::Go)
    }
}
