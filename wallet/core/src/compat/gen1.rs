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
    use kaspa_bip32::{Language, Mnemonic, Prefix as KeyPrefix};

    const GO_SINGLE_V1_CIPHER: &[u8] = &hex!(
        "2022041df1a5bdcc26445952c53f96518641118bf0f990a01747d631d4607e5b53af3c9f4c07d6e3b84bc766445191b13d1f1fdf7ac96eae9c8859a9add660ac15b938356f936fdf614640d89627d368c57b22cf62844b1e1bcf3feceecbc6bf655df9519d7e3cfede6fe19d87a49e5709211b0b95c8d68781c70c4722bd8e25361492ef38d5cca21664a7f0838e4a1e2994d30c6d4b81d1397169570375ce56608439ae00e84c1f6acdd805f0ee22d4ba7b354c7f7cd4b2d18ce4fd6b8af785f95ed2a69361f318bc"
    );
    const GO_SINGLE_V1_SALT: &[u8] = &hex!("044f5b890e48af4a7dcd7e7766af9380");
    const GO_WALLET_V1_NUM_THREADS: u32 = 8;

    fn go_single_v1_encrypted_mnemonic() -> EncryptedMnemonic<&'static [u8]> {
        EncryptedMnemonic { cipher: GO_SINGLE_V1_CIPHER, salt: GO_SINGLE_V1_SALT }
    }

    fn go_single_v1_mnemonic() -> Mnemonic {
        let decrypted = decrypt_mnemonic(GO_WALLET_V1_NUM_THREADS, go_single_v1_encrypted_mnemonic(), b"").unwrap();
        Mnemonic::new(decrypted.trim(), Language::English).unwrap()
    }

    async fn xpub_from_mnemonic(mnemonic: Mnemonic, account_kind: AccountKind, prefix: KeyPrefix) -> String {
        let prv_key_data = PrvKeyData::try_new_from_mnemonic(mnemonic, None, EncryptionKind::XChaCha20Poly1305).unwrap();
        prv_key_data.create_xpub(None, account_kind, 0).await.unwrap().to_string(Some(prefix))
    }

    async fn go_single_v1_bip32_xpub() -> String {
        xpub_from_mnemonic(go_single_v1_mnemonic(), BIP32_ACCOUNT_KIND.into(), KeyPrefix::KPUB).await
    }

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
    async fn import_golang_single_wallet_ecdsa_test() {
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

        let xpublic_key = go_single_v1_bip32_xpub().await;
        let file = SingleWalletFileV1 {
            encrypted_mnemonic: go_single_v1_encrypted_mnemonic(),
            xpublic_key: xpublic_key.as_str(),
            ecdsa: true,
        };
        let import_secret = Secret::new(vec![]);

        let acc = wallet.import_kaspawallet_golang_single_v1(&import_secret, &wallet_secret, file).await.unwrap();
        assert!(acc.ecdsa(), "ECDSA go single-key import preserves the keyfile curve flag");
        assert_eq!(
            acc.receive_address().unwrap(),
            Address::try_from("kaspa:qyp83nlhnrtkjqsty4reakvcgfsj67mn4wzgvclmvcrrqzl6eykmzzqvwzcyned").unwrap(),
            "ECDSA go single-key import matches libkaspawallet Address(..., m/0/0, ecdsa=true)",
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

    #[tokio::test]
    async fn import_golang_multisig_v1_multi_own_local_seats_test() {
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
        let multisig: Arc<crate::account::variants::multisig::MultiSig> = acc.downcast_arc().expect("imported account is multisig");
        assert_eq!(
            multisig.prv_key_data_ids().as_ref().expect("restored local seats").len(),
            2,
            "restored upstream multi-own fixture keeps both own encrypted mnemonics as local seats",
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
        let own_mnemonic = go_single_v1_mnemonic();
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

        let peer_xpubs = [
            "kpub2K9Fpx7HzqLsm2MmZzg9uvPwQ859AEy3eujMHVykyFd9SEp5JtLhkH2KThXP9Ht6Rbstccq7q4MEN358x5FpoXEuVif1qtcj7QwYMaScA7h"
                .to_string(),
            "kpub2KYczbz9ENzcawE7cfc6etFaH147BcAUE4VYxCJmxHRY3bs2KiynfYveZY7uDDybBuNiUahjRoJrQnBzunwTAEEuAzmyNNh4njU88PRHun2"
                .to_string(),
        ];
        let peer_xpub_refs = peer_xpubs.iter().map(String::as_str).collect();
        let file = MultisigWalletFileV1 {
            encrypted_mnemonics: vec![go_single_v1_encrypted_mnemonic()],
            xpublic_keys: peer_xpub_refs,
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
        assert_eq!(
            acc.receive_address().unwrap(),
            Address::try_from("kaspa:pzw6lpv56jyus9grnp8faqrfnz7nugtf7c67e8lhufzrwdcfg6wjueh4843nx").unwrap(),
            "canonical Schnorr multisig import matches libkaspawallet Address(..., m/0/0/0, ecdsa=false)",
        );
    }

    /// A canonical ECDSA multisig keyfile (one own encrypted mnemonic + peer
    /// xpubs, `ecdsa: true`) imports cleanly: the v1-importer ECDSA hard-error
    /// is gone, the own mnemonic is stored as the account's local cosigner
    /// key, and the resulting
    /// account reports the ECDSA curve. Cross-binary ECDSA interop preserved.
    #[tokio::test]
    async fn golang_multisig_file_ecdsa_imports() {
        let own_mnemonic = go_single_v1_mnemonic();
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

        let peer_xpubs = [
            "kpub2HxEtVQadaLTXmWdxEVSs1a3AxY8ZSrv8PhX6VyDU4SZDPN5usC8nijLqrQ2sFtXd5PRbnEh8vBRKXo68ocPSTkBZsYodJrnd6tjTyr7ykW"
                .to_string(),
            "kpub2K4uLKcJUR1HRzrh2eMH52Y3MqQEuQWgAs2Ri1DJURLXy6ysX6FK1ofv6YvrsNfPg9RgvdQvnqBCohtBKx2ZQbMJUzT8AuV3aY3zXx8RVk2"
                .to_string(),
        ];
        let peer_xpub_refs = peer_xpubs.iter().map(String::as_str).collect();
        let file = MultisigWalletFileV1 {
            encrypted_mnemonics: vec![go_single_v1_encrypted_mnemonic()],
            xpublic_keys: peer_xpub_refs,
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
        assert_eq!(
            acc.receive_address().unwrap(),
            Address::try_from("kaspa:pp3jenalh472ku2ad3d0gazae9pws6jgm2hcaux6h2zk4p44566vw2r6tv67e").unwrap(),
            "canonical ECDSA multisig import matches libkaspawallet Address(..., m/1/0/0, ecdsa=true)",
        );
    }

    /// A go multisig keyfile always proves its seat at go's hardcoded
    /// account level 0. Importing it into a wallet that ALREADY holds a
    /// multisig account at slot/seat 0 succeeds: the new group lands at the
    /// next wallet-local slot, the proven embedded index stays 0, and the
    /// group's receive address still matches the go-derived golden address
    /// (the address depends only on the cosigner set, K, and curve - never
    /// on the landing slot).
    #[tokio::test]
    async fn golang_multisig_file_imports_at_busy_slot_zero() {
        let own_mnemonic = go_single_v1_mnemonic();

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

        // Pre-existing group: the same own key at embedded index 0 with a
        // DIFFERENT peer, occupying slot 0.
        let occupying = wallet
            .import_multisig_with_mnemonic(
                &wallet_secret,
                (own_mnemonic, None),
                Some(0),
                2,
                vec![
                    "kpub2HxEtVQadaLTXmWdxEVSs1a3AxY8ZSrv8PhX6VyDU4SZDPN5usC8nijLqrQ2sFtXd5PRbnEh8vBRKXo68ocPSTkBZsYodJrnd6tjTyr7ykW"
                        .to_string(),
                ],
                false,
            )
            .await
            .unwrap();
        assert_eq!(occupying[0].clone().as_derivation_capable().unwrap().account_index(), 0, "the pre-existing group occupies slot 0",);

        let peer_xpubs = [
            "kpub2K9Fpx7HzqLsm2MmZzg9uvPwQ859AEy3eujMHVykyFd9SEp5JtLhkH2KThXP9Ht6Rbstccq7q4MEN358x5FpoXEuVif1qtcj7QwYMaScA7h"
                .to_string(),
            "kpub2KYczbz9ENzcawE7cfc6etFaH147BcAUE4VYxCJmxHRY3bs2KiynfYveZY7uDDybBuNiUahjRoJrQnBzunwTAEEuAzmyNNh4njU88PRHun2"
                .to_string(),
        ];
        let peer_xpub_refs = peer_xpubs.iter().map(String::as_str).collect();
        let file = MultisigWalletFileV1 {
            encrypted_mnemonics: vec![go_single_v1_encrypted_mnemonic()],
            xpublic_keys: peer_xpub_refs,
            required_signatures: 2,
            cosigner_index: 0,
            ecdsa: false,
        };
        let import_secret = Secret::new(vec![]);

        let acc = wallet.import_kaspawallet_golang_multisig_v1(&import_secret, &wallet_secret, file).await.unwrap();
        assert_eq!(
            acc.clone().as_derivation_capable().unwrap().account_index(),
            1,
            "the keyfile group lands at the next wallet-local slot",
        );
        let multisig: Arc<crate::account::variants::multisig::MultiSig> = acc.clone().downcast_arc().expect("account is multisig");
        assert!(multisig.seat_indexes().contains(&0), "the proven embedded index stays 0");
        assert_eq!(
            acc.receive_address().unwrap(),
            Address::try_from("kaspa:pzw6lpv56jyus9grnp8faqrfnz7nugtf7c67e8lhufzrwdcfg6wjueh4843nx").unwrap(),
            "the receive address still matches the go-derived golden address at the new slot",
        );
    }

    /// Two go multisig keyfiles backed by the SAME own mnemonic (both
    /// proving embedded index 0) with different peer sets both import into
    /// one wallet as two accounts at distinct wallet-local slots - the case
    /// a busy-slot rejection used to block.
    #[tokio::test]
    async fn golang_multisig_same_seed_keyfiles_coexist_at_distinct_slots() {
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
        let import_secret = Secret::new(vec![]);

        let peers_first = [
            "kpub2K9Fpx7HzqLsm2MmZzg9uvPwQ859AEy3eujMHVykyFd9SEp5JtLhkH2KThXP9Ht6Rbstccq7q4MEN358x5FpoXEuVif1qtcj7QwYMaScA7h"
                .to_string(),
            "kpub2KYczbz9ENzcawE7cfc6etFaH147BcAUE4VYxCJmxHRY3bs2KiynfYveZY7uDDybBuNiUahjRoJrQnBzunwTAEEuAzmyNNh4njU88PRHun2"
                .to_string(),
        ];
        let first_refs = peers_first.iter().map(String::as_str).collect();
        let first_file = MultisigWalletFileV1 {
            encrypted_mnemonics: vec![go_single_v1_encrypted_mnemonic()],
            xpublic_keys: first_refs,
            required_signatures: 2,
            cosigner_index: 0,
            ecdsa: false,
        };
        let first = wallet.import_kaspawallet_golang_multisig_v1(&import_secret, &wallet_secret, first_file).await.unwrap();

        let peers_second = [
            "kpub2HxEtVQadaLTXmWdxEVSs1a3AxY8ZSrv8PhX6VyDU4SZDPN5usC8nijLqrQ2sFtXd5PRbnEh8vBRKXo68ocPSTkBZsYodJrnd6tjTyr7ykW"
                .to_string(),
            "kpub2K4uLKcJUR1HRzrh2eMH52Y3MqQEuQWgAs2Ri1DJURLXy6ysX6FK1ofv6YvrsNfPg9RgvdQvnqBCohtBKx2ZQbMJUzT8AuV3aY3zXx8RVk2"
                .to_string(),
        ];
        let second_refs = peers_second.iter().map(String::as_str).collect();
        let second_file = MultisigWalletFileV1 {
            encrypted_mnemonics: vec![go_single_v1_encrypted_mnemonic()],
            xpublic_keys: second_refs,
            required_signatures: 2,
            cosigner_index: 0,
            ecdsa: false,
        };
        let second = wallet.import_kaspawallet_golang_multisig_v1(&import_secret, &wallet_secret, second_file).await.unwrap();

        assert_eq!(first.clone().as_derivation_capable().unwrap().account_index(), 0, "first keyfile group lands in slot 0");
        assert_eq!(second.clone().as_derivation_capable().unwrap().account_index(), 1, "second keyfile group lands in slot 1");
        assert_ne!(first.id(), second.id(), "the two same-seed groups are distinct accounts");
    }

    /// Re-importing a go multisig keyfile whose group is already registered
    /// rejects through the duplicate-group guard and stores nothing new.
    #[tokio::test]
    async fn golang_multisig_file_duplicate_group_rejected() {
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
        let import_secret = Secret::new(vec![]);

        let peer_xpubs = [
            "kpub2K9Fpx7HzqLsm2MmZzg9uvPwQ859AEy3eujMHVykyFd9SEp5JtLhkH2KThXP9Ht6Rbstccq7q4MEN358x5FpoXEuVif1qtcj7QwYMaScA7h"
                .to_string(),
            "kpub2KYczbz9ENzcawE7cfc6etFaH147BcAUE4VYxCJmxHRY3bs2KiynfYveZY7uDDybBuNiUahjRoJrQnBzunwTAEEuAzmyNNh4njU88PRHun2"
                .to_string(),
        ];
        let first_refs = peer_xpubs.iter().map(String::as_str).collect();
        let first_file = MultisigWalletFileV1 {
            encrypted_mnemonics: vec![go_single_v1_encrypted_mnemonic()],
            xpublic_keys: first_refs,
            required_signatures: 2,
            cosigner_index: 0,
            ecdsa: false,
        };
        wallet.import_kaspawallet_golang_multisig_v1(&import_secret, &wallet_secret, first_file).await.unwrap();

        let second_refs = peer_xpubs.iter().map(String::as_str).collect();
        let second_file = MultisigWalletFileV1 {
            encrypted_mnemonics: vec![go_single_v1_encrypted_mnemonic()],
            xpublic_keys: second_refs,
            required_signatures: 2,
            cosigner_index: 0,
            ecdsa: false,
        };
        let result = wallet.import_kaspawallet_golang_multisig_v1(&import_secret, &wallet_secret, second_file).await;
        match result {
            Err(crate::error::Error::MultisigGroupAlreadyExists { .. }) => {}
            Ok(_) => panic!("a go keyfile re-registering an existing group must be rejected"),
            Err(other) => panic!("expected MultisigGroupAlreadyExists, got {other:?}"),
        }

        let stored_accounts =
            wallet.store().as_account_store().unwrap().iter(None).await.unwrap().try_collect::<Vec<_>>().await.unwrap();
        assert_eq!(stored_accounts.len(), 1, "duplicate keyfile rejection must not store a second account");
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
