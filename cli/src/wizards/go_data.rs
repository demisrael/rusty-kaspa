use crate::cli::KaspaCli;
use crate::imports::*;
use crate::result::Result;
use kaspa_wallet_core::account::Account;
use kaspa_wallet_core::wallet::{
    EncryptedMnemonic, MultisigWalletFileV0, MultisigWalletFileV1, SingleWalletFileV0, SingleWalletFileV1,
};
use std::path::Path;
use workflow_store::fs;

enum GoWalletFile<'a> {
    SingleV0(SingleWalletFileV0<'a, Vec<u8>>),
    SingleV1(SingleWalletFileV1<'a, Vec<u8>>),
    MultiV0(MultisigWalletFileV0<'a, Vec<u8>>),
    MultiV1(MultisigWalletFileV1<'a, Vec<u8>>),
}

#[derive(Debug, Default, Deserialize)]
struct EncryptedMnemonicIntermediate {
    #[serde(with = "kaspa_utils::serde_bytes")]
    cipher: Vec<u8>,
    #[serde(with = "kaspa_utils::serde_bytes")]
    salt: Vec<u8>,
}

impl From<EncryptedMnemonicIntermediate> for EncryptedMnemonic<Vec<u8>> {
    fn from(value: EncryptedMnemonicIntermediate) -> Self {
        Self { cipher: value.cipher, salt: value.salt }
    }
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct UnifiedWalletIntermediate<'a> {
    version: u8,
    num_threads: Option<u8>,
    encrypted_mnemonics: Vec<EncryptedMnemonicIntermediate>,
    #[serde(borrow)]
    public_keys: Vec<&'a str>,
    minimum_signatures: u16,
    cosigner_index: u8,
    ecdsa: bool,
}

impl<'a> UnifiedWalletIntermediate<'a> {
    fn into_wallet_type(mut self) -> Result<GoWalletFile<'a>> {
        let single = self.encrypted_mnemonics.len() == 1 && self.public_keys.len() == 1;
        match (single, self.version) {
            (true, 0) => Ok(GoWalletFile::SingleV0(SingleWalletFileV0 {
                num_threads: self.num_threads.ok_or_else(|| Error::Custom("go-data v0 keyfile is missing numThreads".into()))? as u32,
                encrypted_mnemonic: std::mem::take(&mut self.encrypted_mnemonics[0]).into(),
                xpublic_key: self.public_keys[0],
                ecdsa: self.ecdsa,
            })),
            (true, 1) => Ok(GoWalletFile::SingleV1(SingleWalletFileV1 {
                encrypted_mnemonic: std::mem::take(&mut self.encrypted_mnemonics[0]).into(),
                xpublic_key: self.public_keys[0],
                ecdsa: self.ecdsa,
            })),
            (false, 0) => Ok(GoWalletFile::MultiV0(MultisigWalletFileV0 {
                num_threads: self.num_threads.ok_or_else(|| Error::Custom("go-data v0 keyfile is missing numThreads".into()))? as u32,
                encrypted_mnemonics: self.encrypted_mnemonics.into_iter().map(EncryptedMnemonic::from).collect(),
                xpublic_keys: self.public_keys,
                required_signatures: self.minimum_signatures,
                cosigner_index: self.cosigner_index,
                ecdsa: self.ecdsa,
            })),
            (false, 1) => Ok(GoWalletFile::MultiV1(MultisigWalletFileV1 {
                encrypted_mnemonics: self.encrypted_mnemonics.into_iter().map(EncryptedMnemonic::from).collect(),
                xpublic_keys: self.public_keys,
                required_signatures: self.minimum_signatures,
                cosigner_index: self.cosigner_index,
                ecdsa: self.ecdsa,
            })),
            (_, version) => Err(Error::Custom(format!("unsupported go-data keyfile version {version}"))),
        }
    }
}

pub(crate) async fn import_into_open_wallet(
    ctx: &Arc<KaspaCli>,
    path: Option<String>,
    wallet_secret: Option<&Secret>,
) -> Result<Arc<dyn Account>> {
    let term = ctx.term();
    let path = match path {
        Some(path) => path,
        None => term.ask(false, "Enter kaspawallet keyfile path: ").await?.trim().to_string(),
    };
    if path.is_empty() {
        return Err(Error::UserAbort);
    }

    let bytes = fs::read(Path::new(&path)).await?;
    let json = String::from_utf8(bytes).map_err(|err| Error::Custom(err.to_string()))?;
    let file: UnifiedWalletIntermediate<'_> = serde_json::from_str(&json)?;
    let file = file.into_wallet_type()?;

    let import_secret = Secret::new(term.ask(true, "Enter kaspawallet keyfile password: ").await?.trim().as_bytes().to_vec());
    let wallet_secret = match wallet_secret {
        Some(secret) => secret.clone(),
        None => Secret::new(term.ask(true, "Enter wallet password: ").await?.trim().as_bytes().to_vec()),
    };
    if wallet_secret.as_ref().is_empty() {
        return Err(Error::WalletSecretRequired);
    }

    let wallet = ctx.wallet();
    let account = match file {
        GoWalletFile::SingleV0(file) => wallet.import_kaspawallet_golang_single_v0(&import_secret, &wallet_secret, file).await?,
        GoWalletFile::SingleV1(file) => wallet.import_kaspawallet_golang_single_v1(&import_secret, &wallet_secret, file).await?,
        GoWalletFile::MultiV0(file) => wallet.import_kaspawallet_golang_multisig_v0(&import_secret, &wallet_secret, file).await?,
        GoWalletFile::MultiV1(file) => wallet.import_kaspawallet_golang_multisig_v1(&import_secret, &wallet_secret, file).await?,
    };
    Ok(account)
}
