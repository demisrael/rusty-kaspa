use crate::cli::KaspaCli;
use crate::imports::*;
use crate::result::Result;
use kaspa_wallet_core::account::MULTISIG_ACCOUNT_KIND;
use kaspa_wallet_core::error::Error as WalletError;
use kaspa_wallet_core::storage::keydata::PrvKeyData;
use kaspa_wallet_core::wallet::{MultisigCurve, max_multisig_cosigners};

pub(crate) async fn create(
    ctx: &Arc<KaspaCli>,
    prv_key_data_info: Arc<PrvKeyDataInfo>,
    account_kind: AccountKind,
    name: Option<&str>,
) -> Result<()> {
    let term = ctx.term();
    let wallet = ctx.wallet();

    let name = if let Some(name) = name {
        Some(name.to_string())
    } else {
        Some(term.ask(false, "Please enter account name (optional, press <enter> to skip): ").await?.trim().to_string())
    };

    if account_kind == MULTISIG_ACCOUNT_KIND {
        return create_multisig(ctx, prv_key_data_info, name).await;
    }

    let wallet_secret = Secret::new(term.ask(true, "Enter wallet password: ").await?.trim().as_bytes().to_vec());
    if wallet_secret.as_ref().is_empty() {
        return Err(Error::WalletSecretRequired);
    }

    let payment_secret = if prv_key_data_info.is_encrypted() {
        let payment_secret = Secret::new(term.ask(true, "Enter payment password: ").await?.trim().as_bytes().to_vec());
        if payment_secret.as_ref().is_empty() {
            return Err(Error::PaymentSecretRequired);
        } else {
            Some(payment_secret)
        }
    } else {
        None
    };

    let ecdsa = ask_curve(&term).await?;

    let account_create_args_bip32 = AccountCreateArgsBip32::new(name, None, ecdsa);
    let account =
        wallet.create_account_bip32(&wallet_secret, prv_key_data_info.id, payment_secret.as_ref(), account_create_args_bip32).await?;

    tprintln!(ctx, "\naccount created: {}\n", account.get_list_string()?);
    wallet.select(Some(&account)).await?;
    Ok(())
}

async fn create_multisig(ctx: &Arc<KaspaCli>, prv_key_data_info: Arc<PrvKeyDataInfo>, account_name: Option<String>) -> Result<()> {
    let term = ctx.term();
    let wallet = ctx.wallet();
    let (wallet_secret, _) = ctx.ask_wallet_secret(None).await?;
    let minimum_signatures: u16 = term.ask(false, "Enter the minimum number of signatures required: ").await?.parse()?;

    let account_index_answer = term.ask(false, "Enter the account index (press <enter> for auto-assign): ").await?;
    let account_index: u64 = match account_index_answer.trim() {
        "" => {
            return Err(Error::Custom(
                "Multisig setup requires an explicit account index. All cosigners must use the same integer for this multisig group; coordinate it with your peers (use 0 for the first multisig in this wallet).".to_string(),
            ));
        }
        s => s.parse()?,
    };

    let ecdsa = ask_curve(&term).await?;

    // Reuse the wallet's single mnemonic; the multisig account is one more
    // hardened child of the same seed that owns every other account in this
    // wallet, mirroring the bip32 wizard above.
    let prv_key_data = wallet
        .store()
        .as_prv_key_data_store()?
        .load_key_data(&wallet_secret, &prv_key_data_info.id)
        .await?
        .ok_or_else(|| WalletError::PrivateKeyNotFound(prv_key_data_info.id))?;

    // Print the wallet's xpub at the chosen account_index before blocking on
    // peer xpubs, so the operator can copy it into their out-of-band channel
    // while the wizard is still waiting for input.
    let xpub_key = derive_multisig_xpub_from_wallet_key(&prv_key_data, account_index).await?;
    let curve_name = if ecdsa { "ecdsa" } else { "schnorr" };
    tprintln!(ctx, "\nextended public key (account_index={account_index}, curve={curve_name}):\n");
    tprintln!(ctx, "{}\n", wallet.network_format_xpub(&xpub_key));

    let prv_key_data_args = vec![PrvKeyDataArgs::new(prv_key_data_info.id, None)];

    let additional_xpub_keys_len: usize = term.ask(false, "Enter the number of additional extended public keys: ").await?.parse()?;
    let total_cosigners = additional_xpub_keys_len + 1;
    check_cosigner_count_under_curve_cap(total_cosigners, minimum_signatures, MultisigCurve::from_ecdsa_bool(ecdsa))?;
    let mut xpub_keys = Vec::with_capacity(additional_xpub_keys_len);
    for i in 1..=additional_xpub_keys_len {
        let xpub_key = term.ask(false, &format!("Enter extended public {i} key: ")).await?;
        xpub_keys.push(xpub_key.trim().to_owned());
    }
    let account = wallet
        .create_account_multisig(
            &wallet_secret,
            prv_key_data_args,
            xpub_keys,
            account_name,
            minimum_signatures,
            ecdsa,
            Some(account_index),
        )
        .await?;

    // Echo the constructed cosigner xpub set in canonical sort order so every
    // operator can confirm their wallet agrees on the full K-of-N group.
    if let Some(keys) = account.xpub_keys() {
        let total = keys.len();
        tprintln!(ctx, "\ncosigner xpub set ({minimum_signatures}-of-{total}):\n");
        for xpub in keys.iter() {
            tprintln!(ctx, "{}", wallet.network_format_xpub(xpub));
        }
        tprintln!(ctx, "");
    }

    tprintln!(ctx, "\naccount created: {}\n", account.get_list_string()?);
    wallet.select(Some(&account)).await?;
    Ok(())
}

/// Derive the wallet's multisig xpub for the operator-entered account_index.
/// The `payment_secret = None` argument matches the wizard invariant (the
/// multisig wizard does not surface a per-account payment password); if a
/// future spec adds one, this call must thread it through.
async fn derive_multisig_xpub_from_wallet_key(
    prv_key_data: &PrvKeyData,
    account_index: u64,
) -> Result<kaspa_bip32::ExtendedPublicKey<kaspa_bip32::secp256k1::PublicKey>> {
    Ok(prv_key_data.create_xpub(None, MULTISIG_ACCOUNT_KIND.into(), account_index).await?)
}

/// Prompt the operator for the account signing curve and return the
/// `ecdsa: bool` selection. Shared between the bip32 single-sig wizard,
/// the multisig wizards (create + watch + import), and the
/// `wallet create` default-account flow. Default-on-empty maps to
/// Schnorr (the modern path); explicit `e`/`ecdsa` (case-insensitive)
/// maps to ECDSA (legacy, RFC 6979 deterministic). Any other answer is
/// rejected with an operator-readable message so the wizard does not
/// silently fall through to an unintended curve.
pub(crate) async fn ask_curve(term: &Arc<Terminal>) -> Result<bool> {
    let answer = term.ask(false, "Signing curve - press <enter> for Schnorr (default), or type 'ecdsa' for ECDSA: ").await?;
    parse_curve_answer(answer.trim())
}

/// Reject a cosigner count that exceeds the curve-aware cap derived from
/// `kaspa_txscript::MAX_SCRIPT_ELEMENT_SIZE` BEFORE the wizard reaches the
/// wallet-core call. The wallet-core layer fires the same error on the
/// same boundary (`Error::MultisigCosignerCountExceedsStandardness`) so
/// the operator-facing message is byte-identical regardless of which
/// layer rejects. Hoisted as a `pub(crate) fn` so the wizard-layer unit
/// tests `create_multisig_wizard_rejects_above_curve_cap` and
/// `multisig_watch_wizard_rejects_above_curve_cap` can drive the contract
/// without an interactive shell.
pub(crate) fn check_cosigner_count_under_curve_cap(total_cosigners: usize, min_sigs: u16, curve: MultisigCurve) -> Result<()> {
    let cap = max_multisig_cosigners(min_sigs, curve);
    if total_cosigners > cap {
        Err(WalletError::MultisigCosignerCountExceedsStandardness { count: total_cosigners, max: cap, curve }.into())
    } else {
        Ok(())
    }
}

/// Parse a curve-prompt answer into the `ecdsa: bool` form the wallet-core
/// account-create APIs consume. Empty input and any case-form of
/// `s`/`schnorr` select Schnorr; case-form of `e`/`ecdsa` selects ECDSA;
/// any other input returns an operator-readable error. Hoisted so the
/// wizard test surface can exercise the parse contract without driving
/// the interactive shell. Shared by the bip32 wizard and the multisig
/// wizards so both surfaces enforce identical operator-facing semantics.
pub(crate) fn parse_curve_answer(s: &str) -> Result<bool> {
    match s.to_ascii_lowercase().as_str() {
        "" | "s" | "schnorr" => Ok(false),
        "e" | "ecdsa" => Ok(true),
        other => Err(Error::Custom(format!(
            "invalid signing curve '{other}'; expected <enter> or 'schnorr' for Schnorr (default), or 'ecdsa' for ECDSA"
        ))),
    }
}

pub(crate) async fn bip32_watch(ctx: &Arc<KaspaCli>, name: Option<&str>) -> Result<()> {
    let term = ctx.term();
    let wallet = ctx.wallet();

    let name = if let Some(name) = name {
        Some(name.to_string())
    } else {
        Some(term.ask(false, "Please enter account name (optional, press <enter> to skip): ").await?.trim().to_string())
    };

    let mut xpub_keys = Vec::with_capacity(1);
    let xpub_key = term.ask(false, "Enter extended public key: ").await?;
    xpub_keys.push(xpub_key.trim().to_owned());

    let wallet_secret = Secret::new(term.ask(true, "Enter wallet password: ").await?.trim().as_bytes().to_vec());
    if wallet_secret.as_ref().is_empty() {
        return Err(Error::WalletSecretRequired);
    }

    let account_create_args_bip32_watch = AccountCreateArgsBip32Watch::new(name, xpub_keys);
    let account = wallet.create_account_bip32_watch(&wallet_secret, account_create_args_bip32_watch).await?;

    tprintln!(ctx, "\naccount created: {}\n", account.get_list_string()?);
    wallet.select(Some(&account)).await?;
    Ok(())
}

pub(crate) async fn multisig_watch(ctx: &Arc<KaspaCli>, name: Option<&str>) -> Result<()> {
    let term = ctx.term();

    let account_name = if let Some(name) = name {
        Some(name.to_string())
    } else {
        Some(term.ask(false, "Please enter account name (optional, press <enter> to skip): ").await?.trim().to_string())
    };

    let term = ctx.term();
    let wallet = ctx.wallet();
    let (wallet_secret, _) = ctx.ask_wallet_secret(None).await?;
    let minimum_signatures: u16 = term.ask(false, "Enter the minimum number of signatures required: ").await?.parse()?;

    let account_index_answer = term.ask(false, "Enter the account index (press <enter> for auto-assign): ").await?;
    let account_index: Option<u64> = match account_index_answer.trim() {
        "" => None,
        s => Some(s.parse()?),
    };

    let ecdsa = ask_curve(&term).await?;

    let prv_key_data_args = Vec::with_capacity(0);

    let answer = term.ask(false, "Enter the number of extended public keys: ").await?.trim().to_string(); //.parse()?;
    let xpub_keys_len: usize = if answer.is_empty() { 0 } else { answer.parse()? };
    check_cosigner_count_under_curve_cap(xpub_keys_len, minimum_signatures, MultisigCurve::from_ecdsa_bool(ecdsa))?;

    let mut xpub_keys = Vec::with_capacity(xpub_keys_len);
    for i in 1..=xpub_keys_len {
        let xpub_key = term.ask(false, &format!("Enter extended public {i} key: ")).await?;
        xpub_keys.push(xpub_key.trim().to_owned());
    }
    let account = wallet
        .create_account_multisig(&wallet_secret, prv_key_data_args, xpub_keys, account_name, minimum_signatures, ecdsa, account_index)
        .await?;

    tprintln!(ctx, "\naccount created: {}\n", account.get_list_string()?);
    wallet.select(Some(&account)).await?;
    Ok(())
}

#[cfg(all(test, not(target_arch = "wasm32")))]
mod tests {
    use super::*;
    use kaspa_bip32::{Language, Mnemonic};
    use kaspa_wallet_core::encryption::EncryptionKind;
    use kaspa_wallet_core::wallet::Wallet;
    use kaspa_wallet_core::wallet::args::WalletCreateArgs;

    const ACCOUNT_INDEX: u64 = 7;

    fn make_prv_key_data() -> PrvKeyData {
        // Deterministic constant-fill entropy via the canonical
        // `Mnemonic::from_entropy` constructor -- reproducible across runs
        // without an embedded phrase literal.
        let mnemonic = Mnemonic::from_entropy(vec![0xc3; 32], Language::English).unwrap();
        PrvKeyData::try_new_from_mnemonic(mnemonic, None, EncryptionKind::XChaCha20Poly1305).unwrap()
    }

    async fn make_seeded_test_wallet() -> (Arc<Wallet>, Secret, PrvKeyData) {
        let resident_store = Wallet::resident_store().unwrap();
        let wallet = Arc::new(Wallet::try_new(resident_store, None, Some(NetworkId::with_suffix(NetworkType::Testnet, 10))).unwrap());
        let wallet_secret = Secret::new(vec![]);
        wallet
            .create_wallet(
                &wallet_secret,
                WalletCreateArgs {
                    title: None,
                    filename: None,
                    encryption_kind: EncryptionKind::XChaCha20Poly1305,
                    user_hint: None,
                    overwrite_wallet_storage: false,
                },
            )
            .await
            .unwrap();
        let prv_key_data = make_prv_key_data();
        let prv_key_data_store = wallet.store().as_prv_key_data_store().unwrap();
        prv_key_data_store.store(&wallet_secret, prv_key_data.clone()).await.unwrap();
        wallet.store().commit(&wallet_secret).await.unwrap();
        (wallet, wallet_secret, prv_key_data)
    }

    async fn count_prv_key_data_entries(wallet: &Arc<Wallet>) -> usize {
        wallet.store().as_prv_key_data_store().unwrap().iter().await.unwrap().try_collect::<Vec<_>>().await.unwrap().len()
    }

    /// The wizard's xpub-derivation primitive returns the same
    /// `ExtendedPublicKey` as a direct call to `PrvKeyData::create_xpub`
    /// at `(payment_secret = None, account_kind = multisig, account_index)`.
    /// Locks in the derivation contract the wizard prints to the operator;
    /// any future drift in the free function's call site fails this test.
    #[tokio::test]
    async fn derive_multisig_xpub_from_wallet_key_is_byte_equal_to_create_xpub() {
        let prv_key_data = make_prv_key_data();
        let derived = derive_multisig_xpub_from_wallet_key(&prv_key_data, ACCOUNT_INDEX).await.unwrap();
        let direct = prv_key_data.create_xpub(None, MULTISIG_ACCOUNT_KIND.into(), ACCOUNT_INDEX).await.unwrap();
        assert_eq!(
            derived.to_string(Some(kaspa_bip32::Prefix::XPUB)),
            direct.to_string(Some(kaspa_bip32::Prefix::XPUB)),
            "derive_multisig_xpub_from_wallet_key must match direct create_xpub byte for byte",
        );
    }

    /// The xpub the wizard prints mid-flow
    /// matches the xpub `Wallet::create_account_multisig` derives internally
    /// for the constructed account. Feeds the same `PrvKeyData` and the same
    /// `account_index` to both paths and asserts byte-equal output via the
    /// constructed account's `xpub_keys()` accessor (the same accessor the
    /// post-construction cosigner-set echo reads).
    #[tokio::test]
    async fn derive_multisig_xpub_from_wallet_key_matches_create_account_multisig_internal_derivation() {
        let (wallet, wallet_secret, prv_key_data) = make_seeded_test_wallet().await;
        let wizard_xpub = derive_multisig_xpub_from_wallet_key(&prv_key_data, ACCOUNT_INDEX).await.unwrap();
        let wizard_xpub_str = wallet.network_format_xpub(&wizard_xpub);

        let prv_key_data_args = vec![PrvKeyDataArgs::new(prv_key_data.id, None)];
        let account = wallet
            .create_account_multisig(&wallet_secret, prv_key_data_args, vec![], None, 1, false, Some(ACCOUNT_INDEX))
            .await
            .unwrap();

        let account_xpubs = account.xpub_keys().expect("multisig account exposes xpub_keys");
        assert_eq!(account_xpubs.len(), 1, "self-multisig with zero external cosigners has exactly one persisted xpub");
        let constructed_xpub_str = wallet.network_format_xpub(&account_xpubs[0]);
        assert_eq!(
            wizard_xpub_str, constructed_xpub_str,
            "mid-flow xpub (printed to operator) must equal the xpub the constructed account stores",
        );
    }

    /// Running the wizard's create path against an existing
    /// wallet PrvKeyData does not append a new `PrvKeyData` entry to the
    /// wallet's `prv_key_data_store`. Counts the store iter before and
    /// after `Wallet::create_account_multisig` (the wizard's only
    /// store-touching call after the key is loaded) and asserts the count
    /// is unchanged.
    #[tokio::test]
    async fn create_multisig_does_not_add_to_prv_key_data_store() {
        let (wallet, wallet_secret, prv_key_data) = make_seeded_test_wallet().await;
        let count_before = count_prv_key_data_entries(&wallet).await;
        assert_eq!(count_before, 1, "seeded wallet has exactly one PrvKeyData entry to start");

        let prv_key_data_args = vec![PrvKeyDataArgs::new(prv_key_data.id, None)];
        wallet.create_account_multisig(&wallet_secret, prv_key_data_args, vec![], None, 1, false, Some(ACCOUNT_INDEX)).await.unwrap();

        let count_after = count_prv_key_data_entries(&wallet).await;
        assert_eq!(count_after, count_before, "wizard's create path must not add a fresh PrvKeyData entry");
    }

    /// Wizard-layer cosigner-count reject: the hoisted
    /// `check_cosigner_count_under_curve_cap` helper returns the
    /// `MultisigCosignerCountExceedsStandardness` error variant when the
    /// requested total exceeds `max_multisig_cosigners(min_sigs, curve)`,
    /// without reaching `Wallet::create_account_multisig`. Boundary
    /// derived from the helper so the test stays correct under any future
    /// hardfork that widens `MAX_SCRIPT_ELEMENT_SIZE`.
    #[tokio::test]
    async fn create_multisig_wizard_rejects_above_curve_cap() {
        for curve in [MultisigCurve::Schnorr, MultisigCurve::Ecdsa] {
            let cap = max_multisig_cosigners(2, curve);
            let total_cosigners = cap + 1;
            let err = check_cosigner_count_under_curve_cap(total_cosigners, 2, curve)
                .expect_err("above-cap cosigner total must reject at wizard-layer");
            match err {
                Error::WalletError(WalletError::MultisigCosignerCountExceedsStandardness { count, max, curve: err_curve }) => {
                    assert_eq!(count, total_cosigners, "{curve:?}: rejection names the supplied total");
                    assert_eq!(max, cap, "{curve:?}: rejection names the curve-aware cap");
                    assert_eq!(err_curve, curve, "{curve:?}: rejection names the curve under test");
                }
                other => panic!("{curve:?}: expected MultisigCosignerCountExceedsStandardness, got {other:?}"),
            }
        }
    }

    /// Wizard-layer mirror for the `multisig_watch` shape: the
    /// xpub_keys_len total (no local seed in the watch wizard) flows
    /// through the same hoisted check. Pins the parity with
    /// `create_multisig_wizard_rejects_above_curve_cap`.
    #[tokio::test]
    async fn multisig_watch_wizard_rejects_above_curve_cap() {
        for curve in [MultisigCurve::Schnorr, MultisigCurve::Ecdsa] {
            let cap = max_multisig_cosigners(2, curve);
            let xpub_keys_len = cap + 1;
            let err = check_cosigner_count_under_curve_cap(xpub_keys_len, 2, curve)
                .expect_err("multisig_watch above-cap xpub_keys_len must reject at wizard-layer");
            match err {
                Error::WalletError(WalletError::MultisigCosignerCountExceedsStandardness { count, max, curve: err_curve }) => {
                    assert_eq!(count, xpub_keys_len, "{curve:?}: rejection names the supplied total");
                    assert_eq!(max, cap, "{curve:?}: rejection names the curve-aware cap");
                    assert_eq!(err_curve, curve);
                }
                other => panic!("{curve:?}: expected MultisigCosignerCountExceedsStandardness, got {other:?}"),
            }
        }
    }

    /// Wizard-layer ECDSA prompt parse: empty + 's'/'schnorr' default to
    /// Schnorr (`false`); 'e'/'ecdsa' map to ECDSA (`true`); any other
    /// answer returns `Error::Custom`. Pins the parse contract so the
    /// interactive REPL never silently picks an unintended curve.
    #[tokio::test]
    async fn parse_curve_answer_accepts_default_schnorr_and_explicit_ecdsa() {
        for ans in ["", "s", "S", "schnorr", "Schnorr", "SCHNORR"] {
            assert!(!parse_curve_answer(ans).unwrap(), "answer={ans:?} maps to Schnorr");
        }
        for ans in ["e", "E", "ecdsa", "Ecdsa", "ECDSA"] {
            assert!(parse_curve_answer(ans).unwrap(), "answer={ans:?} maps to ECDSA");
        }
        for ans in ["foo", "scnhorr", "bls", "1"] {
            let err = parse_curve_answer(ans).expect_err("invalid curve answer must reject");
            match err {
                Error::Custom(msg) => assert!(msg.contains(ans), "error names the supplied value: {msg}"),
                other => panic!("expected Error::Custom for {ans:?}, got {other:?}"),
            }
        }
    }
}
