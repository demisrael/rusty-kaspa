use crate::KaspaCli;
use crate::error::Error;
use crate::imports::*;
use crate::result::Result;
use kaspa_bip32::{Language, Mnemonic, WordCount};
use kaspa_wallet_core::account::{BIP32_ACCOUNT_KIND, LEGACY_ACCOUNT_KIND, MULTISIG_ACCOUNT_KIND};
use std::sync::Arc;

/// Word-count gate for the mnemonic-import arms. Legacy accounts use the
/// fixed 12-word gen0 scheme; bip32 and multisig accept any word count the
/// wallet's mnemonic codec itself supports (`WordCount`: 12 or 24), so the
/// gate stays in lockstep with what `Mnemonic::new` will accept downstream.
fn validate_mnemonic_word_count(account_kind: &AccountKind, length: usize) -> Result<()> {
    match account_kind.as_ref() {
        LEGACY_ACCOUNT_KIND if length != 12 => Err(Error::Custom(format!("wrong mnemonic length ({length})"))),
        BIP32_ACCOUNT_KIND | MULTISIG_ACCOUNT_KIND if WordCount::try_from(length).is_err() => {
            Err(Error::Custom(format!("wrong mnemonic length ({length})")))
        }
        LEGACY_ACCOUNT_KIND | BIP32_ACCOUNT_KIND | MULTISIG_ACCOUNT_KIND => Ok(()),
        _ => Err(Error::Custom("unsupported account kind".to_owned())),
    }
}

pub async fn prompt_for_mnemonic(term: &Arc<Terminal>) -> Result<Vec<String>> {
    let mut words: Vec<String> = vec![];
    loop {
        if words.is_empty() {
            tprintln!(term, "Please enter mnemonic (12 or 24 space separated words)");
        } else if words.len() < 12 {
            let remains_for_12 = 12 - words.len();
            let remains_for_24 = 24 - words.len();
            tprintln!(term, "Please enter additional {} or {} words or <enter> to abort", remains_for_12, remains_for_24);
        } else {
            let remains_for_24 = 24 - words.len();
            tprintln!(term, "Please enter additional {} words or <enter> to abort", remains_for_24);
        }
        let text = term.ask(false, "Mnemonic:").await?;
        let list = text.split_whitespace().map(|s| s.to_string()).collect::<Vec<String>>();
        if list.is_empty() {
            return Err(Error::UserAbort);
        }
        words.extend(list);

        if words.len() > 24 || words.len() == 12 || words.len() == 24 {
            break;
        }
    }

    if words.len() > 24 { Err("Mnemonic must be 12 or 24 words".into()) } else { Ok(words) }
}

pub(crate) async fn import_with_mnemonic(ctx: &Arc<KaspaCli>, account_kind: AccountKind, additional_xpubs: &[String]) -> Result<()> {
    let wallet = ctx.wallet();

    if !wallet.is_open() {
        return Err(Error::WalletIsNotOpen);
    }

    let term = ctx.term();

    tprintln!(ctx);
    let wallet_secret = Secret::new(term.ask(true, "Enter wallet password: ").await?.trim().as_bytes().to_vec());
    tprintln!(ctx);
    let mnemonic = prompt_for_mnemonic(&term).await?;
    tprintln!(ctx);
    validate_mnemonic_word_count(&account_kind, mnemonic.len())?;

    let payment_secret = if account_kind == LEGACY_ACCOUNT_KIND {
        None
    } else {
        tpara!(
            ctx,
            "\
            \
            If your original wallet has a bip39 recovery passphrase, please enter it now.\
            \
            Specifically, this is not a wallet password. This is a secondary mnemonic passphrase\
            used to encrypt your mnemonic. This is known as a 'payment passphrase'\
            'mnemonic passphrase', or a 'recovery passphrase'. If your mnemonic was created\
            with a payment passphrase and you do not enter it now, the import process\
            will generate a different private key.\
            \
            If you do not have a bip39 recovery passphrase, press ENTER.\
            \
            ",
        );

        let payment_secret = term.ask(true, "Enter payment password (optional): ").await?;
        if payment_secret.trim().is_empty() { None } else { Some(Secret::new(payment_secret.trim().as_bytes().to_vec())) }
    };

    let mnemonic = mnemonic.join(" ");
    let mnemonic = Mnemonic::new(mnemonic.trim(), Language::English)?;

    let account = if account_kind != MULTISIG_ACCOUNT_KIND {
        wallet.import_with_mnemonic(&wallet_secret, payment_secret.as_ref(), mnemonic, account_kind).await?
    } else {
        let mut mnemonics_secrets = vec![(mnemonic, payment_secret)];
        while matches!(
            term.ask(false, "Do you want to add more mnemonics (type 'y' to approve)?: ").await?.trim(),
            "y" | "Y" | "YES" | "yes"
        ) {
            tprintln!(ctx);
            let mnemonic = prompt_for_mnemonic(&term).await?;
            tprintln!(ctx);
            let payment_secret = term.ask(true, "Enter payment password (optional): ").await?;
            let payment_secret = payment_secret.trim().is_not_empty().then(|| Secret::new(payment_secret.trim().as_bytes().to_vec()));
            let mnemonic = mnemonic.join(" ");
            let mnemonic = Mnemonic::new(mnemonic.trim(), Language::English)?;

            mnemonics_secrets.push((mnemonic, payment_secret));
        }

        let mut additional_xpubs = additional_xpubs.to_vec();
        if additional_xpubs.is_empty() {
            loop {
                let xpub_key = term.ask(false, "Enter extended public key: (empty to skip or stop)").await?;
                if xpub_key.is_empty() {
                    break;
                }
                additional_xpubs.push(xpub_key.trim().to_owned());
            }
        }
        let n_required: u16 = term.ask(false, "Enter the minimum number of signatures required: ").await?.parse()?;

        let ecdsa = crate::wizards::account::ask_curve(&term).await?;

        wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_secrets, n_required, additional_xpubs, ecdsa).await?
    };

    tprintln!(ctx, "\naccount imported: {}\n", account.get_list_string()?);
    wallet.select(Some(&account)).await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The bip32 and multisig import arms accept every word count the
    /// wallet's mnemonic codec supports (12 and 24); the legacy arm is
    /// pinned to the fixed 12-word gen0 scheme; counts outside the codec
    /// set are rejected before any further prompting.
    #[test]
    fn mnemonic_word_count_gate_tracks_wallet_codec() {
        let bip32: AccountKind = BIP32_ACCOUNT_KIND.into();
        let legacy: AccountKind = LEGACY_ACCOUNT_KIND.into();
        let multisig: AccountKind = MULTISIG_ACCOUNT_KIND.into();

        for accepted in [12, 24] {
            assert!(validate_mnemonic_word_count(&bip32, accepted).is_ok(), "bip32 accepts {accepted} words");
            assert!(validate_mnemonic_word_count(&multisig, accepted).is_ok(), "multisig accepts {accepted} words");
        }
        assert!(validate_mnemonic_word_count(&legacy, 12).is_ok(), "legacy accepts the 12-word gen0 scheme");
        assert!(validate_mnemonic_word_count(&legacy, 24).is_err(), "legacy rejects 24 words");
        for rejected in [11, 13, 18, 23, 25] {
            assert!(validate_mnemonic_word_count(&bip32, rejected).is_err(), "bip32 rejects {rejected} words");
            assert!(validate_mnemonic_word_count(&multisig, rejected).is_err(), "multisig rejects {rejected} words");
        }
        assert!(validate_mnemonic_word_count(&AccountKind::from("hello world"), 12).is_err(), "unsupported kind rejected");
    }
}
