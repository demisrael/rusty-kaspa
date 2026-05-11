//! Verbatim port of the Go daemon's `estimateFee` and
//! `estimateFeePerInput` helpers.
//!
//! Source: https://github.com/kaspanet/kaspad/blob/4bb5bf25d3f2279ec2a61c3b4f7bb083b5f522b2/cmd/kaspawallet/daemon/server/create_unsigned_transaction.go#L263
//!
//! `estimate_fee` builds a worst-case mock transaction (using
//! ECDSA-public-key fake addresses, since ECDSA scriptPubKey is the
//! longest standard form), runs it through
//! [`crate::mass::estimate_mass_after_signatures`], and returns
//! `min(ceil(mass * fee_rate), max_fee)` -- mirroring Go's
//! `min(uint64(math.Ceil(float64(mass)*feeRate)), maxFee)`.
//!
//! Reuse-existing-crates discipline: the fake address comes from
//! [`kaspa_addresses::Address::new`] with
//! `Version::PubKeyECDSA` + a 33-byte all-zero payload (mirrors
//! Go's `util.NewAddressPublicKeyECDSA(fakePubKey[:],
//! params.Prefix)` where `fakePubKey` is a zeroed
//! `[util.PublicKeySizeECDSA]byte`). Mass calc is delegated to the
//! crate's existing mass primitive; nothing in this module
//! computes mass itself.

use kaspa_addresses::{Address, Prefix as AddrPrefix, Version as AddrVersion};
use kaspa_consensus_core::config::params::Params;
use kaspa_consensus_core::tx::{ScriptPublicKey, UtxoEntry};

use super::error::CoinSelectError;
use crate::mass::{estimate_compute_mass_after_signatures, estimate_mass_after_signatures};
use crate::transaction::{Payment, Utxo, create_unsigned_transaction, outpoint};

/// Length of an ECDSA public-key payload as stored in a kaspa
/// address. Mirrors Go's `util.PublicKeySizeECDSA = 33`
/// (`util/address.go` -- 33 = 1-byte SEC compressed prefix +
/// 32-byte X-coordinate). The Go reference uses
/// `[util.PublicKeySizeECDSA]byte{}` (a zeroed array) as the fake
/// pubkey for fee-estimation mass calcs.
const ECDSA_PUBLIC_KEY_LEN: usize = 33;

/// Wallet configuration the fee / coin-selection layer needs in
/// order to build the mock unsigned transactions whose mass it
/// estimates. Mirrors the relevant subset of Go's `*server` state
/// the `estimateFee` / `selectUTXOs` paths read
/// (`s.keysFile.ExtendedPublicKeys`, `s.keysFile.MinimumSignatures`,
/// `s.params.Prefix`).
#[derive(Clone, Debug)]
pub struct WalletConfig {
    /// Cosigner xpub strings as stored in the keyfile. The
    /// in-memory order does not matter -- both
    /// [`create_unsigned_transaction`] and [`estimate_fee`] sort
    /// the slice in-place via
    /// [`crate::transaction::sort_extended_public_keys`] before
    /// every per-input pair-construction loop.
    pub extended_public_keys: Vec<String>,

    /// Minimum cosigner signatures required to spend a UTXO.
    /// `1` for single-key wallets; `M` for an N-of-M multisig
    /// keyfile. Mirrors Go's `s.keysFile.MinimumSignatures`.
    pub minimum_signatures: u32,

    /// Address prefix for the active network -- needed to
    /// construct the fake-address fee-estimation mocks.
    /// Mirrors Go's `s.params.Prefix`.
    pub address_prefix: AddrPrefix,

    /// Wallet keyfile's `ecdsa` flag. Selects the redeem-script
    /// opcode (`OpCheckMultiSig` vs `OpCheckMultiSigECDSA`) and the
    /// cosigner pubkey serialization (32-byte x-only vs 33-byte
    /// compressed) when assembling the junk-filled sigscript for
    /// mass estimation. Mirrors Go's `s.keysFile.ECDSA`.
    pub ecdsa: bool,
}

/// Verbatim port of Go's `estimateFee`
/// (`create_unsigned_transaction.go:263-310`). Computes the
/// post-signing fee in sompi for the supplied `selected_utxos` set,
/// modelling the recipient/change-output split as Go does:
///
/// - If `total_value > recipient_value`: two outputs (one
///   `recipient_value`, one `total_value - recipient_value`).
///   Fees are not subtracted from the change because the Go
///   reference's comment "We ignore the fee since we expect it to
///   be insignificant in mass calculation" applies here too --
///   mass depends on output count + scriptPubKey length, not
///   exact amounts.
/// - Otherwise (recipient takes everything): one output of
///   `total_value`.
///
/// The mock unsigned transaction is then run through
/// [`estimate_mass_after_signatures`], the mass is multiplied by
/// `fee_rate` (ceiling), and the result is clamped to `max_fee`.
pub fn estimate_fee(
    cfg: &WalletConfig,
    params: &Params,
    selected_utxos: &[Utxo],
    fee_rate: f64,
    max_fee: u64,
    recipient_value: u64,
) -> Result<u64, CoinSelectError> {
    let fake_addr = Address::new(cfg.address_prefix, AddrVersion::PubKeyECDSA, &[0u8; ECDSA_PUBLIC_KEY_LEN]);

    let total_value: u64 = selected_utxos.iter().map(|u| u.utxo_entry.amount).sum();
    let mock_payments: Vec<Payment> = if total_value > recipient_value {
        vec![
            Payment { address: fake_addr.clone(), amount: recipient_value },
            Payment { address: fake_addr, amount: total_value - recipient_value },
        ]
    } else {
        vec![Payment { address: fake_addr, amount: total_value }]
    };

    let mock_pst = create_unsigned_transaction(&cfg.extended_public_keys, cfg.minimum_signatures, &mock_payments, selected_utxos)?;
    let mass = estimate_mass_after_signatures(&mock_pst, params, cfg.ecdsa)?;

    Ok(scale_mass_to_fee(mass, fee_rate, max_fee))
}

/// Verbatim port of Go's `estimateFeePerInput`
/// (`create_unsigned_transaction.go:312-354`). Used by the
/// merge-transaction path
/// ([`super::split::more_utxos_for_merge_transaction`]) to figure
/// out the marginal mass cost of one extra input.
///
/// The implementation mirrors Go line-for-line:
///
/// 1. Build a mock single-UTXO transaction with a deterministic
///    zero outpoint and an empty `ScriptPublicKey` (Go uses
///    `ScriptPublicKey{Script: nil, Version: 0}`); empty payment
///    list (Go: `nil`); derivation path `"m"`.
/// 2. Build a mock zero-UTXO transaction with the same empty
///    payment list.
/// 3. Estimate compute-only mass for both; subtract to get
///    `input_mass`.
/// 4. Return `floor(input_mass * fee_rate)` (Go: `uint64(float64(...)
///    * feeRate)`; no `math.Ceil` here -- direct cast).
///
/// The Go reference deliberately uses `compute_mass` instead of
/// the `max(compute, storage)` overall mass to avoid divide-by-zero
/// in the storage-mass denominator under unusual UTXO shapes;
/// [`estimate_compute_mass_after_signatures`] is the matching
/// compute-only entry point in [`crate::mass`].
pub fn estimate_fee_per_input(cfg: &WalletConfig, params: &Params, fee_rate: f64) -> Result<u64, CoinSelectError> {
    let mock_utxo = mock_zero_utxo();

    let mock_tx_with_input =
        create_unsigned_transaction(&cfg.extended_public_keys, cfg.minimum_signatures, &[], std::slice::from_ref(&mock_utxo))?;
    let mass_with_input = estimate_compute_mass_after_signatures(&mock_tx_with_input, params, cfg.ecdsa)?;

    let mock_tx_without_input = create_unsigned_transaction(&cfg.extended_public_keys, cfg.minimum_signatures, &[], &[])?;
    let mass_without_input = estimate_compute_mass_after_signatures(&mock_tx_without_input, params, cfg.ecdsa)?;

    let input_mass = mass_with_input.saturating_sub(mass_without_input);
    Ok((input_mass as f64 * fee_rate) as u64)
}

/// Mock UTXO matching Go's `estimateFeePerInput` worst-case input
/// shape (`create_unsigned_transaction.go:312-323`):
/// `Outpoint{TransactionID: 0, Index: 0}`,
/// `UTXOEntry{Amount: 1, ScriptPublicKey: empty, blockDaaScore:
/// 0, isCoinbase: false}`, `DerivationPath: "m"`.
fn mock_zero_utxo() -> Utxo {
    Utxo {
        outpoint: outpoint([0u8; 32], 0),
        utxo_entry: UtxoEntry {
            amount: 1,
            script_public_key: ScriptPublicKey::new(0, vec![].into()),
            block_daa_score: 0,
            is_coinbase: false,
        },
        derivation_path: "m".to_string(),
    }
}

/// Apply the Go reference's
/// `min(uint64(math.Ceil(float64(mass)*feeRate)), maxFee)` to a
/// mass + fee-rate pair. Extracted as its own helper so unit tests
/// can pin the arithmetic without re-deriving a mass.
fn scale_mass_to_fee(mass: u64, fee_rate: f64, max_fee: u64) -> u64 {
    let scaled = (mass as f64 * fee_rate).ceil();
    // f64 -> u64 saturates on negative or NaN (we never produce
    // those given mass >= 0 and the policy floor fee_rate >= 1).
    // Cast via clamp to avoid undefined behaviour on overflow.
    let scaled_u64 = if scaled.is_finite() && scaled >= 0.0 && scaled <= u64::MAX as f64 { scaled as u64 } else { u64::MAX };
    scaled_u64.min(max_fee)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scale_mass_to_fee_ceiling_then_clamp() {
        // 1000 mass * 1.5 fee_rate = 1500 sompi
        assert_eq!(scale_mass_to_fee(1000, 1.5, 10_000), 1500);
        // ceiling: 1000 * 1.0001 = 1000.1 -> ceil 1001
        assert_eq!(scale_mass_to_fee(1000, 1.0001, 10_000), 1001);
        // clamp: 1000 * 100.0 = 100_000, max_fee = 50_000
        assert_eq!(scale_mass_to_fee(1000, 100.0, 50_000), 50_000);
        // zero mass -> zero fee
        assert_eq!(scale_mass_to_fee(0, 1.0, 10_000), 0);
    }

    #[test]
    fn test_scale_mass_to_fee_overflow_saturates_to_max_fee() {
        // f64 -> u64 with overflow saturates to u64::MAX, then
        // clamped down to max_fee.
        assert_eq!(scale_mass_to_fee(u64::MAX, 1e18, 12345), 12345);
    }

    #[test]
    fn test_mock_zero_utxo_matches_go_shape() {
        // Pin the Go `estimateFeePerInput` worst-case input shape:
        // outpoint = (zero_hash, 0); amount = 1; empty script;
        // derivation_path = "m".
        let m = mock_zero_utxo();
        assert_eq!(m.utxo_entry.amount, 1);
        assert_eq!(m.derivation_path, "m");
        let outp = m.outpoint;
        assert_eq!(outp.index, 0);
        let txid_bytes = outp.transaction_id.expect("txid populated").bytes;
        assert_eq!(txid_bytes, vec![0u8; 32]);
    }
}
