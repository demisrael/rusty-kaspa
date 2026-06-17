use crate::imports::*;
use crate::wizards;

#[derive(Default, Handler)]
#[help("Wallet management operations")]
pub struct Wallet;

impl Wallet {
    async fn main(self: Arc<Self>, ctx: &Arc<dyn Context>, mut argv: Vec<String>, cmd: &str) -> Result<()> {
        let ctx = ctx.clone().downcast_arc::<KaspaCli>()?;

        let guard = ctx.wallet().guard();
        let guard = guard.lock().await;

        if argv.is_empty() {
            return self.display_help(ctx, argv).await;
        }

        let op = argv.remove(0);
        match op.as_str() {
            "list" => {
                let wallets = ctx.store().wallet_list().await?;
                if wallets.is_empty() {
                    tprintln!(ctx, "No wallets found");
                } else {
                    tprintln!(ctx, "");
                    tprintln!(ctx, "Wallets:");
                    tprintln!(ctx, "");
                    for wallet in wallets {
                        if let Some(title) = wallet.title {
                            tprintln!(ctx, "  {}: {}", wallet.filename, title);
                        } else {
                            tprintln!(ctx, "  {}", wallet.filename);
                        }
                    }
                    tprintln!(ctx, "");
                }
            }
            "create" | "import" => {
                let container = if let Some(position) = argv.iter().position(|arg| arg == "--container") {
                    argv.remove(position);
                    true
                } else {
                    false
                };

                if op.as_str() == "import" && argv.first().map(String::as_str) == Some("go-data") {
                    argv.remove(0);
                    if argv.len() > 2 {
                        tprintln!(ctx, "usage: 'wallet import go-data [<path>] [<name>]'");
                        tprintln!(ctx, "too many arguments: {}\r\n", argv.join(" "));
                        return Ok(());
                    }
                    let keyfile_path = if argv.is_empty() { None } else { Some(argv.remove(0)) };
                    let wallet_name = if argv.is_empty() {
                        None
                    } else {
                        let name = argv.remove(0);
                        let name = name.trim().to_string();
                        if name.to_lowercase().as_str() == "wallet" {
                            return Err(Error::custom("Wallet name cannot be 'wallet'"));
                        }
                        Some(name)
                    };
                    let wallet_secret = wizards::wallet::create_container(&ctx, Some(guard), wallet_name.as_deref()).await?;
                    let account = wizards::go_data::import_into_open_wallet(&ctx, keyfile_path, Some(&wallet_secret)).await?;
                    tprintln!(ctx, "\naccount imported: {}\n", account.get_list_string()?);
                    ctx.wallet().select(Some(&account)).await?;
                    return Ok(());
                }

                let multisig = take_multisig_import_alias(op.as_str(), &mut argv);

                let wallet_name = if argv.is_empty() {
                    None
                } else {
                    let name = argv.remove(0);
                    let name = name.trim().to_string();
                    let name_check = name.to_lowercase();
                    if name_check.as_str() == "wallet" {
                        return Err(Error::custom("Wallet name cannot be 'wallet'"));
                    }
                    Some(name)
                };

                let wallet_name = wallet_name.as_deref();
                if container {
                    if op.as_str() != "create" {
                        return Err(Error::custom("--container is supported with 'wallet create'"));
                    }
                    wizards::wallet::create_container(&ctx, Some(guard), wallet_name).await?;
                    return Ok(());
                }
                let import_with_mnemonic = op.as_str() == "import";
                wizards::wallet::create(&ctx, guard.into(), wallet_name, import_with_mnemonic, multisig).await?;
            }
            "open" => {
                let name = if let Some(name) = argv.first().cloned() {
                    let name_check = name.to_lowercase();

                    if name_check.as_str() == "wallet" {
                        tprintln!(ctx, "you can not have a wallet named 'wallet'...");
                        tprintln!(ctx, "perhaps you are looking to use 'open <name>'");
                        return Ok(());
                    }
                    Some(name)
                } else {
                    ctx.wallet().settings().get(WalletSettings::Wallet).clone()
                };

                let (wallet_secret, _) = ctx.ask_wallet_secret(None).await?;
                let _ = ctx.notifier().show(Notification::Processing).await;
                let args = WalletOpenArgs::default_with_legacy_accounts();
                ctx.wallet().open(&wallet_secret, name, args, &guard).await?;
                ctx.wallet().activate_accounts(None, &guard).await?;
            }
            "close" => {
                ctx.wallet().close().await?;
            }
            "hint" => {
                if !argv.is_empty() {
                    let re = regex::Regex::new(r"wallet\s+hint\s+").unwrap();
                    let hint = re.replace(cmd, "");
                    let hint = hint.trim();
                    let store = ctx.store();
                    if hint == "remove" {
                        tprintln!(ctx, "Hint is empty - removing wallet hint");
                        store.set_user_hint(None).await?;
                    } else {
                        store.set_user_hint(Some(hint.into())).await?;
                    }
                } else {
                    tprintln!(ctx, "usage:\n'wallet hint <text>' or 'wallet hint remove' to remove the hint");
                }
            }
            v => {
                tprintln!(ctx, "unknown command: '{v}'");
                return self.display_help(ctx, argv).await;
            }
        }

        Ok(())
    }

    async fn display_help(self: Arc<Self>, ctx: Arc<KaspaCli>, _argv: Vec<String>) -> Result<()> {
        ctx.term().help(
            &[
                ("list", "List available local wallet files"),
                ("create [--container] [<name>]", "Create a new bip32 wallet, or an empty wallet container with --container"),
                (
                    "import [mnemonic] [<name>]",
                    "Create a wallet from an existing mnemonic; single-sig bip32 accounts \
                with a balance are discovered automatically. \r\n\r\n\
                To import legacy wallets (KDX or kaspanet) please create \
                a new bip32 wallet and use the 'account import' command. \
                Legacy wallets can only be imported as accounts. \
                \r\n",
                ),
                ("import go-data [<path>] [<name>]", "Create an empty wallet container and import a kaspawallet Go keyfile. \r\n"),
                (
                    "import multisig [<name>] / import mnemonic multisig [<name>]",
                    "Create a wallet from an existing mnemonic and register a multisig \
                account in one pass (prompts for the full cosigner extended public key set and \
                the minimum number of signatures). \r\n",
                ),
                ("open [<name>]", "Open an existing wallet (shorthand: 'open [<name>]')"),
                ("close", "Close an opened wallet (shorthand: 'close')"),
                ("hint", "Change the wallet phishing hint"),
            ],
            None,
        )?;

        Ok(())
    }
}

fn take_multisig_import_alias(op: &str, argv: &mut Vec<String>) -> bool {
    if op != "import" {
        return false;
    }
    if argv.first().map(String::as_str) == Some("multisig") {
        argv.remove(0);
        return true;
    }
    if argv.first().map(String::as_str) == Some("mnemonic") {
        argv.remove(0);
        if argv.first().map(String::as_str) == Some("multisig") {
            argv.remove(0);
            return true;
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::take_multisig_import_alias;

    #[test]
    fn wallet_import_multisig_aliases_route_to_guarded_import() {
        let mut short = vec!["multisig".to_string(), "cosigner-a".to_string()];
        assert!(take_multisig_import_alias("import", &mut short));
        assert_eq!(short, vec!["cosigner-a".to_string()]);

        let mut long = vec!["mnemonic".to_string(), "multisig".to_string(), "cosigner-a".to_string()];
        assert!(take_multisig_import_alias("import", &mut long));
        assert_eq!(long, vec!["cosigner-a".to_string()]);
    }

    #[test]
    fn wallet_import_non_multisig_forms_keep_existing_arguments() {
        let mut restore = vec!["mnemonic".to_string(), "cosigner-a".to_string()];
        assert!(!take_multisig_import_alias("import", &mut restore));
        assert_eq!(restore, vec!["cosigner-a".to_string()]);

        let mut create = vec!["multisig".to_string(), "cosigner-a".to_string()];
        assert!(!take_multisig_import_alias("create", &mut create));
        assert_eq!(create, vec!["multisig".to_string(), "cosigner-a".to_string()]);
    }
}
