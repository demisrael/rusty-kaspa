use crate::imports::*;
use chacha20poly1305::{Key, KeyInit, aead::AeadMut};

pub fn decrypt_mnemonic<T: AsRef<[u8]>>(
    num_threads: u32,
    EncryptedMnemonic { cipher, salt }: EncryptedMnemonic<T>,
    pass: &[u8],
) -> Result<String> {
    let params = argon2::ParamsBuilder::new().t_cost(1).m_cost(64 * 1024).p_cost(num_threads).output_len(32).build().unwrap();
    let mut key = [0u8; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, Default::default(), params).hash_password_into(
        pass,
        salt.as_ref(),
        &mut key[..],
    )?;
    let mut aead = chacha20poly1305::XChaCha20Poly1305::new(Key::from_slice(&key));
    let (nonce, ciphertext) = cipher.as_ref().split_at(24);

    let decrypted = aead.decrypt(nonce.into(), ciphertext)?;
    Ok(String::from_utf8(decrypted)?)
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod test {
    use super::*;
    use hex_literal::hex;
    use kaspa_addresses::Address;

    #[test]
    fn decrypt_go_encrypted_mnemonics_test() {
        let file = SingleWalletFileV1{
            encrypted_mnemonic: EncryptedMnemonic {
                cipher: hex!("2022041df1a5bdcc26445952c53f96518641118bf0f990a01747d631d4607e5b53af3c9f4c07d6e3b84bc766445191b13d1f1fdf7ac96eae9c8859a9add660ac15b938356f936fdf614640d89627d368c57b22cf62844b1e1bcf3feceecbc6bf655df9519d7e3cfede6fe19d87a49e5709211b0b95c8d68781c70c4722bd8e25361492ef38d5cca21664a7f0838e4a1e2994d30c6d4b81d1397169570375ce56608439ae00e84c1f6acdd805f0ee22d4ba7b354c7f7cd4b2d18ce4fd6b8af785f95ed2a69361f318bc").as_slice(),
                salt: hex!("044f5b890e48af4a7dcd7e7766af9380").as_slice(),
            },
            xpublic_key: "kpub2KUE88roSn5peP1rEZnbRuKYw1fEPbhqBoXVWW7mLfkrLvQBAjUqwx7m1ezeSfqfecv9RUYePuHf99iW51i31WjwWjnzKDCUcTucBSiBbJA",
            ecdsa: false,
        };

        let decrypted = decrypt_mnemonic(8, file.encrypted_mnemonic, b"");
        log_info!("decrypted: {decrypted:?}");
        assert!(decrypted.is_ok(), "decrypt error");
        assert_eq!(
            "dizzy uncover funny time weapon chat volume squirrel comic motion until diamond response remind hurt spider door strategy entire oyster hawk marriage soon fabric",
            decrypted.unwrap()
        );
    }

    #[tokio::test]
    async fn import_golang_single_wallet_test() {
        let resident_store = Wallet::resident_store().unwrap();
        let wallet = Arc::new(Wallet::try_new(resident_store, None, Some(NetworkId::new(NetworkType::Mainnet))).unwrap());
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

        let file = SingleWalletFileV1{
            encrypted_mnemonic: EncryptedMnemonic {
                cipher: hex!("2022041df1a5bdcc26445952c53f96518641118bf0f990a01747d631d4607e5b53af3c9f4c07d6e3b84bc766445191b13d1f1fdf7ac96eae9c8859a9add660ac15b938356f936fdf614640d89627d368c57b22cf62844b1e1bcf3feceecbc6bf655df9519d7e3cfede6fe19d87a49e5709211b0b95c8d68781c70c4722bd8e25361492ef38d5cca21664a7f0838e4a1e2994d30c6d4b81d1397169570375ce56608439ae00e84c1f6acdd805f0ee22d4ba7b354c7f7cd4b2d18ce4fd6b8af785f95ed2a69361f318bc").as_slice(),
                salt: hex!("044f5b890e48af4a7dcd7e7766af9380").as_slice(),
            },
            xpublic_key: "kpub2KUE88roSn5peP1rEZnbRuKYw1fEPbhqBoXVWW7mLfkrLvQBAjUqwx7m1ezeSfqfecv9RUYePuHf99iW51i31WjwWjnzKDCUcTucBSiBbJA",
            ecdsa: false,
        };
        let import_secret = Secret::new(vec![]);

        let acc = wallet.import_kaspawallet_golang_single_v1(&import_secret, &wallet_secret, file).await.unwrap();
        assert_eq!(
            acc.receive_address().unwrap(),
            Address::try_from("kaspa:qpuvlauc6a5syze9g70dnxzzvykhkuatsjrx87mxqccqh7kf9kcssdkp9ec7w").unwrap(), // taken from golang impl
        );
    }

    #[tokio::test]
    async fn import_golang_multisig_v1_wallet_test() {
        let resident_store = Wallet::resident_store().unwrap();
        let wallet = Arc::new(Wallet::try_new(resident_store, None, Some(NetworkId::new(NetworkType::Mainnet))).unwrap());
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

        let file = MultisigWalletFileV1{
            encrypted_mnemonics: vec![
                EncryptedMnemonic {
                    cipher: hex!("f587dbc539b5303605e7065f4a473caffc91d5992dc0c4ec0b111e5362aa089c6ed034d4165697c13776777fa6a9396b0396515f75fa8fa34d13a3abdbf126bf8575be389177998c77170f3dba80c18d7cb5e223802cd4df51584ea280c08f31a8ecccca31000f4ebd78d584ba95ad2424b57a2945c60a7a36174bf69ecf251c141f01644aeb10268f3321bc2114a24da8ab8983540224e494634889a48f846ceea4238869d1e397f041f5594c53453ea63606a4bb50").as_slice(),
                    salt: hex!("04fb57493be318c3bb1cddb6dde05e09").as_slice(), 
                },
                EncryptedMnemonic {
                    cipher: hex!("2244d1b757e635cec13347d8b6d57c446063b9b72f54c425055eefd983c11cd4d75b0303e47848b5df29991056769c109cad73844fcc4de3d68122fdc09ec31a9e26334cb65141de1fb74718fd44e1d7312eaf975871833026569f06624f02ea79ba189e2db8cbfc4a1ada7fc4801179fb9b838618418043a335e8e01ab9dc8b6b8a1aa963a827a7914bab0815337d3955e5d2a4fc2df738506d5eb537ca7c52c690106bde9d2b686949a2e651099311796df3698499e8606cdbdc9963fc9172b12b").as_slice(),
                    salt: hex!("60405c5b3a180e4fdebd5a6d5c51bf76").as_slice(),
                },
            ],
            xpublic_keys: vec![
                "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK",
                "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
                "kpub2JZg9pofE54nqvkhFRRx18pAMhYDPL2CpYqBx2AkzvsEknCh8V4rtez9ZYeab3HCW1Xsm9f4d6J5dfJVg9NADWN7rtqNft21batcii1SjXy",
                "kpub2HuRXjAmhs3KwQ9WpHVaiHRjBP37TQUiUGFQBTwp7cdbArCo5s2MT6415nd3ZYaELvNbZ4qTJjCGTavExv514tWftaGQzCK8gQz6BQJNySp",
                "kpub2KCvcuKVgfy1h7PvCw4xFcdLAPoerVZBG4qTo8vRGH2Qe6p5AgLyRek5CEnuCDkduXHqgwtvaVfYYBS7gQBR1J4XowdvqvPXsHZGA5WyRJF",
            ],
            required_signatures: 2,
            cosigner_index: 1,
            ecdsa: false,
        };
        let import_secret = Secret::new(vec![]);

        let acc = wallet.import_kaspawallet_golang_multisig_v1(&import_secret, &wallet_secret, file).await.unwrap();
        assert_eq!(
            acc.receive_address().unwrap(),
            Address::try_from("kaspa:pqvgkyjeuxmd8k70egrrzpdz5rqj0acmr6y94mwsltxfp6nc50742295c3998").unwrap(), // taken from golang impl
        );
    }

    /// A canonical kaspawallet multisig keyfile carries exactly ONE own
    /// encrypted mnemonic (NumPrivateKeys default 1) + the peer cosigner
    /// xpubs. It imports cleanly: the own mnemonic is stored as the account's
    /// local cosigner key and the peer xpubs register the cosigner group (cross-binary interop
    /// preserved). The own encrypted mnemonic here is a genuine go-encrypted
    /// fixture (the same cipher the single-wallet decrypt test exercises),
    /// decrypted under the multisig v1 thread count.
    #[tokio::test]
    async fn golang_multisig_file_canonical_imports() {
        use crate::account::variants::multisig::MULTISIG_ACCOUNT_KIND;
        use kaspa_bip32::{Language, Mnemonic};

        let own_cipher = hex!(
            "2022041df1a5bdcc26445952c53f96518641118bf0f990a01747d631d4607e5b53af3c9f4c07d6e3b84bc766445191b13d1f1fdf7ac96eae9c8859a9add660ac15b938356f936fdf614640d89627d368c57b22cf62844b1e1bcf3feceecbc6bf655df9519d7e3cfede6fe19d87a49e5709211b0b95c8d68781c70c4722bd8e25361492ef38d5cca21664a7f0838e4a1e2994d30c6d4b81d1397169570375ce56608439ae00e84c1f6acdd805f0ee22d4ba7b354c7f7cd4b2d18ce4fd6b8af785f95ed2a69361f318bc"
        );
        let own_salt = hex!("044f5b890e48af4a7dcd7e7766af9380");

        // Recover the own mnemonic's PrvKeyData id so we can assert the
        // account's local seat references it after import.
        let decrypted =
            decrypt_mnemonic(8, EncryptedMnemonic { cipher: own_cipher.as_slice(), salt: own_salt.as_slice() }, b"").unwrap();
        let own_mnemonic = Mnemonic::new(decrypted.trim(), Language::English).unwrap();
        let own_id = PrvKeyData::try_new_from_mnemonic(own_mnemonic, None, EncryptionKind::XChaCha20Poly1305).unwrap().id;

        let resident_store = Wallet::resident_store().unwrap();
        let wallet = Arc::new(Wallet::try_new(resident_store, None, Some(NetworkId::new(NetworkType::Mainnet))).unwrap());
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

        let file = MultisigWalletFileV1 {
            encrypted_mnemonics: vec![EncryptedMnemonic { cipher: own_cipher.as_slice(), salt: own_salt.as_slice() }],
            xpublic_keys: vec![
                "kpub2J937qL9n85s7HrhYyYYdMkzq1kaMiAf9PAcJzRW3jV7NgntNfGGrNgut7ZxcVrJqH42BCT2WyjfnxJh3SBDjLhXHe3UC2RJUu5tcjsViuK",
                "kpub2Jtuqt6WJWZv3fQUnKhuEaCxbAyzLsFn3UEEaM4g7CXa2LZjQZH4o6tpj83tFaewMEyX56qrAF4Q64uqunVyBayuuRNwjru5DWchDEcq5vz",
            ],
            required_signatures: 2,
            cosigner_index: 0,
            ecdsa: false,
        };
        let import_secret = Secret::new(vec![]);

        let acc = wallet.import_kaspawallet_golang_multisig_v1(&import_secret, &wallet_secret, file).await.unwrap();
        assert_eq!(acc.account_kind(), MULTISIG_ACCOUNT_KIND, "import yields a multisig account");
        let multisig: Arc<crate::account::variants::multisig::MultiSig> = acc.clone().downcast_arc().expect("account is multisig");
        assert_eq!(
            multisig.prv_key_data_ids().as_ref().expect("local seat")[0],
            own_id,
            "the keyfile's single own mnemonic backs the account's local seat",
        );
        assert_eq!(acc.xpub_keys().map(|x| x.len()), Some(3), "the cosigner set registers own + the two peer xpubs (2-of-3)");
    }

    /// A canonical ECDSA multisig keyfile (one own encrypted mnemonic + peer
    /// xpubs, `ecdsa: true`) imports cleanly: the v1-importer ECDSA hard-error
    /// is gone, the own mnemonic is stored as the account's local cosigner
    /// key, and the resulting
    /// account reports the ECDSA curve. Cross-binary ECDSA interop preserved.
    #[tokio::test]
    async fn golang_multisig_file_ecdsa_imports() {
        use crate::account::variants::multisig::MULTISIG_ACCOUNT_KIND;
        use kaspa_bip32::{Language, Mnemonic};

        let own_cipher = hex!(
            "2022041df1a5bdcc26445952c53f96518641118bf0f990a01747d631d4607e5b53af3c9f4c07d6e3b84bc766445191b13d1f1fdf7ac96eae9c8859a9add660ac15b938356f936fdf614640d89627d368c57b22cf62844b1e1bcf3feceecbc6bf655df9519d7e3cfede6fe19d87a49e5709211b0b95c8d68781c70c4722bd8e25361492ef38d5cca21664a7f0838e4a1e2994d30c6d4b81d1397169570375ce56608439ae00e84c1f6acdd805f0ee22d4ba7b354c7f7cd4b2d18ce4fd6b8af785f95ed2a69361f318bc"
        );
        let own_salt = hex!("044f5b890e48af4a7dcd7e7766af9380");

        let decrypted =
            decrypt_mnemonic(8, EncryptedMnemonic { cipher: own_cipher.as_slice(), salt: own_salt.as_slice() }, b"").unwrap();
        let own_mnemonic = Mnemonic::new(decrypted.trim(), Language::English).unwrap();
        let own_id = PrvKeyData::try_new_from_mnemonic(own_mnemonic, None, EncryptionKind::XChaCha20Poly1305).unwrap().id;

        let resident_store = Wallet::resident_store().unwrap();
        let wallet = Arc::new(Wallet::try_new(resident_store, None, Some(NetworkId::new(NetworkType::Mainnet))).unwrap());
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

        let file = MultisigWalletFileV1 {
            encrypted_mnemonics: vec![EncryptedMnemonic { cipher: own_cipher.as_slice(), salt: own_salt.as_slice() }],
            xpublic_keys: vec![
                "kpub2JZg9pofE54nqvkhFRRx18pAMhYDPL2CpYqBx2AkzvsEknCh8V4rtez9ZYeab3HCW1Xsm9f4d6J5dfJVg9NADWN7rtqNft21batcii1SjXy",
                "kpub2HuRXjAmhs3KwQ9WpHVaiHRjBP37TQUiUGFQBTwp7cdbArCo5s2MT6415nd3ZYaELvNbZ4qTJjCGTavExv514tWftaGQzCK8gQz6BQJNySp",
            ],
            required_signatures: 2,
            cosigner_index: 0,
            ecdsa: true,
        };
        let import_secret = Secret::new(vec![]);

        let acc = wallet.import_kaspawallet_golang_multisig_v1(&import_secret, &wallet_secret, file).await.unwrap();
        assert_eq!(acc.account_kind(), MULTISIG_ACCOUNT_KIND, "ECDSA import yields a multisig account");
        assert!(acc.ecdsa(), "the imported account reports the ECDSA curve");
        let multisig: Arc<crate::account::variants::multisig::MultiSig> = acc.clone().downcast_arc().expect("account is multisig");
        assert_eq!(
            multisig.prv_key_data_ids().as_ref().expect("local seat")[0],
            own_id,
            "the ECDSA keyfile's single own mnemonic backs the account's local seat",
        );
    }

    #[test]
    fn deser_golang_wallet_test() {
        #[allow(dead_code)]
        #[derive(Debug)]
        enum WalletType<'a> {
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

        #[derive(serde_repr::Deserialize_repr, PartialEq, Debug)]
        #[repr(u8)]
        enum WalletVersion {
            Zero = 0,
            One = 1,
        }
        #[derive(Debug, Deserialize)]
        #[serde(rename_all = "camelCase")]
        struct UnifiedWalletIntermediate<'a> {
            version: WalletVersion,
            num_threads: Option<u8>,
            encrypted_mnemonics: Vec<EncryptedMnemonicIntermediate>,
            #[serde(borrow)]
            public_keys: Vec<&'a str>,
            minimum_signatures: u16,
            cosigner_index: u8,
            ecdsa: bool,
        }

        impl<'a> UnifiedWalletIntermediate<'a> {
            fn into_wallet_type(mut self) -> WalletType<'a> {
                let single = self.encrypted_mnemonics.len() == 1 && self.public_keys.len() == 1;
                match (single, self.version) {
                    (true, WalletVersion::Zero) => WalletType::SingleV0(SingleWalletFileV0 {
                        num_threads: self.num_threads.expect("num_threads must present in case of v0") as u32,
                        encrypted_mnemonic: std::mem::take(&mut self.encrypted_mnemonics[0]).into(),
                        xpublic_key: self.public_keys[0],
                        ecdsa: self.ecdsa,
                    }),
                    (true, WalletVersion::One) => WalletType::SingleV1(SingleWalletFileV1 {
                        encrypted_mnemonic: std::mem::take(&mut self.encrypted_mnemonics[0]).into(),
                        xpublic_key: self.public_keys[0],
                        ecdsa: self.ecdsa,
                    }),
                    (false, WalletVersion::Zero) => WalletType::MultiV0(MultisigWalletFileV0 {
                        num_threads: self.num_threads.expect("num_threads must present in case of v0") as u32,
                        encrypted_mnemonics: self
                            .encrypted_mnemonics
                            .into_iter()
                            .map(|EncryptedMnemonicIntermediate { cipher, salt }| EncryptedMnemonic { cipher, salt })
                            .collect(),
                        xpublic_keys: self.public_keys,
                        required_signatures: self.minimum_signatures,
                        cosigner_index: self.cosigner_index,
                        ecdsa: self.ecdsa,
                    }),
                    (false, WalletVersion::One) => WalletType::MultiV1(MultisigWalletFileV1 {
                        encrypted_mnemonics: self
                            .encrypted_mnemonics
                            .into_iter()
                            .map(|EncryptedMnemonicIntermediate { cipher, salt }| EncryptedMnemonic { cipher, salt })
                            .collect(),
                        xpublic_keys: self.public_keys,
                        required_signatures: self.minimum_signatures,
                        cosigner_index: self.cosigner_index,
                        ecdsa: self.ecdsa,
                    }),
                }
            }
        }

        let single_json_v0 = r#"{"numThreads":8,"version":0,"encryptedMnemonics":[{"cipher":"2022041df1a5bdcc26445952c53f96518641118bf0f990a01747d631d4607e5b53af3c9f4c07d6e3b84bc766445191b13d1f1fdf7ac96eae9c8859a9add660ac15b938356f936fdf614640d89627d368c57b22cf62844b1e1bcf3feceecbc6bf655df9519d7e3cfede6fe19d87a49e5709211b0b95c8d68781c70c4722bd8e25361492ef38d5cca21664a7f0838e4a1e2994d30c6d4b81d1397169570375ce56608439ae00e84c1f6acdd805f0ee22d4ba7b354c7f7cd4b2d18ce4fd6b8af785f95ed2a69361f318bc","salt":"044f5b890e48af4a7dcd7e7766af9380"}],"publicKeys":["kpub2KUE88roSn5peP1rEZnbRuKYw1fEPbhqBoXVWW7mLfkrLvQBAjUqwx7m1ezeSfqfecv9RUYePuHf99iW51i31WjwWjnzKDCUcTucBSiBbJA"],"minimumSignatures":1,"cosignerIndex":0,"lastUsedExternalIndex":0,"lastUsedInternalIndex":0,"ecdsa":false}"#.to_owned();
        let single_json_v1 = r#"{"version":1,"encryptedMnemonics":[{"cipher":"2022041df1a5bdcc26445952c53f96518641118bf0f990a01747d631d4607e5b53af3c9f4c07d6e3b84bc766445191b13d1f1fdf7ac96eae9c8859a9add660ac15b938356f936fdf614640d89627d368c57b22cf62844b1e1bcf3feceecbc6bf655df9519d7e3cfede6fe19d87a49e5709211b0b95c8d68781c70c4722bd8e25361492ef38d5cca21664a7f0838e4a1e2994d30c6d4b81d1397169570375ce56608439ae00e84c1f6acdd805f0ee22d4ba7b354c7f7cd4b2d18ce4fd6b8af785f95ed2a69361f318bc","salt":"044f5b890e48af4a7dcd7e7766af9380"}],"publicKeys":["kpub2KUE88roSn5peP1rEZnbRuKYw1fEPbhqBoXVWW7mLfkrLvQBAjUqwx7m1ezeSfqfecv9RUYePuHf99iW51i31WjwWjnzKDCUcTucBSiBbJA"],"minimumSignatures":1,"cosignerIndex":0,"lastUsedExternalIndex":0,"lastUsedInternalIndex":0,"ecdsa":false}"#.to_owned();

        let unified: UnifiedWalletIntermediate = serde_json::from_str(&single_json_v0).unwrap();
        assert!(matches!(unified.into_wallet_type(), WalletType::SingleV0(_)));
        let unified: UnifiedWalletIntermediate = serde_json::from_str(&single_json_v1).unwrap();
        assert!(matches!(unified.into_wallet_type(), WalletType::SingleV1(_)));
    }
}
