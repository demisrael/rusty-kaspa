//!
//! # Kaspa wallet runtime implementation.
//!
//! This module contains a Rust implementation of the Kaspa wallet that
//! can be used in native Rust as well as WASM32 (Browser, NodeJs, Bun)
//! environments.
//!
//! This wallet is not meant to be used directly, but rather through the
//! use of the [`WalletApi`] trait.
//!

pub mod api;
pub mod args;
pub mod maps;
pub use args::*;

use crate::account::ScanNotifier;
use crate::api::traits::WalletApi;
use crate::compat::gen1::decrypt_mnemonic;
use crate::error::Error::Custom;
use crate::factory::try_load_account;
use crate::imports::*;
use crate::settings::{SettingsStore, WalletSettings};
use crate::storage::interface::{OpenArgs, StorageDescriptor};
use crate::storage::local::Storage;
use crate::storage::local::interface::LocalStore;
use crate::wallet::keydata::PrvKeyDataVariantKind;
use crate::wallet::maps::ActiveAccountMap;
use kaspa_bip32::{ExtendedKey, Language, Mnemonic, Prefix as KeyPrefix, WordCount};
use kaspa_notify::{
    listener::ListenerId,
    scope::{Scope, VirtualDaaScoreChangedScope},
};
use kaspa_wallet_keys::xpub::NetworkTaggedXpub;
use kaspa_wrpc_client::{KaspaRpcClient, Resolver, WrpcEncoding};
use workflow_core::task::spawn;

pub type WalletGuard<'l> = AsyncMutexGuard<'l, ()>;

#[derive(Debug)]
pub struct EncryptedMnemonic<T: AsRef<[u8]>> {
    pub cipher: T, // raw
    pub salt: T,   // raw
}

#[derive(Debug)]
pub struct SingleWalletFileV0<'a, T: AsRef<[u8]>> {
    pub num_threads: u32,
    pub encrypted_mnemonic: EncryptedMnemonic<T>,
    pub xpublic_key: &'a str,
    pub ecdsa: bool,
}

#[derive(Debug)]
pub struct SingleWalletFileV1<'a, T: AsRef<[u8]>> {
    pub encrypted_mnemonic: EncryptedMnemonic<T>,
    pub xpublic_key: &'a str,
    pub ecdsa: bool,
}

impl<T: AsRef<[u8]>> SingleWalletFileV1<'_, T> {
    const NUM_THREADS: u32 = 8;
}

#[derive(Debug)]
pub struct MultisigWalletFileV0<'a, T: AsRef<[u8]>> {
    pub num_threads: u32,
    pub encrypted_mnemonics: Vec<EncryptedMnemonic<T>>,
    pub xpublic_keys: Vec<&'a str>, // includes pub keys from encrypted
    pub required_signatures: u16,
    pub cosigner_index: u8,
    pub ecdsa: bool,
}

#[derive(Debug)]
pub struct MultisigWalletFileV1<'a, T: AsRef<[u8]>> {
    pub encrypted_mnemonics: Vec<EncryptedMnemonic<T>>,
    pub xpublic_keys: Vec<&'a str>, // includes pub keys from encrypted
    pub required_signatures: u16,
    pub cosigner_index: u8,
    pub ecdsa: bool,
}

impl<T: AsRef<[u8]>> MultisigWalletFileV1<'_, T> {
    const NUM_THREADS: u32 = 8;
}

#[derive(Clone)]
pub enum WalletBusMessage {
    Discovery { record: TransactionRecord },
}

/// Internal wallet state.
struct Inner {
    active_accounts: ActiveAccountMap,
    legacy_accounts: ActiveAccountMap,
    listener_id: Mutex<Option<ListenerId>>,
    task_ctl: DuplexChannel,
    selected_account: Mutex<Option<Arc<dyn Account>>>,
    store: Arc<dyn Interface>,
    settings: SettingsStore<WalletSettings>,
    utxo_processor: Arc<UtxoProcessor>,
    multiplexer: Multiplexer<Box<Events>>,
    wallet_bus: Channel<WalletBusMessage>,
    estimation_abortables: Mutex<HashMap<AccountId, Abortable>>,
    retained_contexts: Mutex<HashMap<String, Arc<Vec<u8>>>>,
    // Mutex used to protect concurrent access to accounts at the wallet api level
    guard: Arc<AsyncMutex<()>>,
    account_guard: Arc<AsyncMutex<()>>,
}

///
/// `Wallet` represents a single wallet instance.
/// It is the main data structure responsible for
/// managing a runtime wallet.
///
/// @category Wallet API
///
#[derive(Clone)]
pub struct Wallet {
    inner: Arc<Inner>,
}

impl Default for Wallet {
    fn default() -> Self {
        let storage = Wallet::local_store().expect("Unable to initialize local storage");
        Wallet::try_new(storage, None, None).unwrap()
    }
}

impl Wallet {
    pub fn local_store() -> Result<Arc<dyn Interface>> {
        Ok(Arc::new(LocalStore::try_new(false)?))
    }

    pub fn resident_store() -> Result<Arc<dyn Interface>> {
        Ok(Arc::new(LocalStore::try_new(true)?))
    }

    pub fn try_new(storage: Arc<dyn Interface>, resolver: Option<Resolver>, network_id: Option<NetworkId>) -> Result<Wallet> {
        Wallet::try_with_wrpc(storage, resolver, network_id)
    }

    pub fn try_with_wrpc(store: Arc<dyn Interface>, resolver: Option<Resolver>, network_id: Option<NetworkId>) -> Result<Wallet> {
        let rpc_client =
            Arc::new(KaspaRpcClient::new_with_args(WrpcEncoding::Borsh, Some("wrpc://127.0.0.1:17110"), resolver, network_id, None)?);

        let rpc_ctl = rpc_client.ctl().clone();
        let rpc_api: Arc<DynRpcApi> = rpc_client;
        let rpc = Rpc::new(rpc_api, rpc_ctl);
        Self::try_with_rpc(Some(rpc), store, network_id)
    }

    pub fn try_with_rpc(rpc: Option<Rpc>, store: Arc<dyn Interface>, network_id: Option<NetworkId>) -> Result<Wallet> {
        let multiplexer = Multiplexer::<Box<Events>>::new();
        let wallet_bus = Channel::unbounded();
        let utxo_processor =
            Arc::new(UtxoProcessor::new(rpc.clone(), network_id, Some(multiplexer.clone()), Some(wallet_bus.clone())));

        let wallet = Wallet {
            inner: Arc::new(Inner {
                multiplexer,
                store,
                active_accounts: ActiveAccountMap::default(),
                legacy_accounts: ActiveAccountMap::default(),
                listener_id: Mutex::new(None),
                task_ctl: DuplexChannel::oneshot(),
                selected_account: Mutex::new(None),
                settings: SettingsStore::new_with_storage(Storage::default_settings_store()),
                utxo_processor: utxo_processor.clone(),
                wallet_bus,
                estimation_abortables: Mutex::new(HashMap::new()),
                retained_contexts: Mutex::new(HashMap::new()),
                guard: Arc::new(AsyncMutex::new(())),
                account_guard: Arc::new(AsyncMutex::new(())),
            }),
        };

        Ok(wallet)
    }

    pub fn to_arc(self) -> Arc<Self> {
        Arc::new(self)
    }

    /// Helper fn for creating the wallet using a builder pattern.
    pub fn with_network_id(self, network_id: NetworkId) -> Self {
        self.set_network_id(&network_id).expect("Unable to set network id");
        self
    }

    pub fn with_resolver(self, resolver: Resolver) -> Self {
        self.wrpc_client().set_resolver(resolver).expect("Unable to set resolver");
        self
    }

    pub fn with_url(self, url: Option<&str>) -> Self {
        self.wrpc_client().set_url(url).expect("Unable to set url");
        self
    }

    //
    // Mutex used to protect concurrent access to accounts
    // at the wallet api level. This is a global lock that
    // is required by various wallet operations.
    //
    // Due to the fact that Rust Wallet API is async, it is
    // possible for clients to concurrently execute API calls
    // that can "trip over each-other", causing incorrect
    // account states.
    //
    pub fn guard(&self) -> Arc<AsyncMutex<()>> {
        self.inner.guard.clone()
    }

    pub fn is_resident(&self) -> Result<bool> {
        Ok(self.store().location()? == StorageDescriptor::Resident)
    }

    pub fn utxo_processor(&self) -> &Arc<UtxoProcessor> {
        &self.inner.utxo_processor
    }

    pub fn descriptor(&self) -> Option<WalletDescriptor> {
        self.store().descriptor()
    }

    pub fn store(&self) -> &Arc<dyn Interface> {
        &self.inner.store
    }

    pub fn active_accounts(&self) -> &ActiveAccountMap {
        &self.inner.active_accounts
    }
    pub fn legacy_accounts(&self) -> &ActiveAccountMap {
        &self.inner.legacy_accounts
    }

    pub async fn reset(self: &Arc<Self>, clear_legacy_cache: bool) -> Result<()> {
        self.utxo_processor().cleanup().await?;

        self.select(None).await?;

        let accounts = self.active_accounts().collect();
        let futures = accounts.into_iter().map(|account| account.stop());
        join_all(futures).await.into_iter().collect::<Result<Vec<_>>>()?;

        if clear_legacy_cache {
            self.legacy_accounts().clear();
        }

        Ok(())
    }

    pub async fn reload(self: &Arc<Self>, reactivate: bool, _guard: &WalletGuard<'_>) -> Result<()> {
        if self.is_open() {
            // similar to reset(), but effectively reboots the wallet

            // let _guard = self.inner.guard.lock().await;

            let accounts = self.active_accounts().collect();
            let account_descriptors = Some(accounts.iter().map(|account| account.descriptor()).collect::<Result<Vec<_>>>()?);
            let wallet_descriptor = self.store().descriptor();

            // shutdown all accounts
            let futures = accounts.iter().map(|account| account.clone().stop());
            join_all(futures).await.into_iter().collect::<Result<Vec<_>>>()?;

            // reset utxo processor
            self.utxo_processor().cleanup().await?;

            // notify reload event
            self.notify(Events::WalletReload { wallet_descriptor, account_descriptors }).await?;

            // if `reactivate` is false, it is the responsibility of the client
            // to re-activate accounts. just like with WalletOpen, the client
            // should fetch transaction history and only then re-activate the accounts.

            if reactivate {
                // restarting accounts will post discovery and balance events
                let futures = accounts.into_iter().map(|account| account.start());
                join_all(futures).await.into_iter().collect::<Result<Vec<_>>>()?;
            }
        }

        Ok(())
    }

    pub async fn close(self: &Arc<Wallet>) -> Result<()> {
        if self.is_open() {
            self.reset(true).await?;
            self.store().close().await?;
            self.notify(Events::WalletClose).await?;
        }

        Ok(())
    }

    cfg_if! {
        if #[cfg(not(feature = "multi-user"))] {

            fn default_active_account(&self) -> Option<Arc<dyn Account>> {
                self.active_accounts().first()
            }

            /// For end-user wallets only - selects an account only if there
            /// is only a single account currently active in the wallet.
            /// Can be used to automatically select the default account.
            pub async fn autoselect_default_account_if_single(self: &Arc<Wallet>) -> Result<()> {
                if self.active_accounts().len() == 1 {
                    self.select(self.default_active_account().as_ref()).await?;
                }
                Ok(())
            }

            /// Select an account as 'active'. Supply `None` to remove active selection.
            pub async fn select(self: &Arc<Self>, account: Option<&Arc<dyn Account>>) -> Result<()> {
                *self.inner.selected_account.lock().unwrap() = account.cloned();
                if let Some(account) = account {
                    // log_info!("selecting account: {}", account.name_or_id());
                    account.clone().start().await?;
                    self.notify(Events::AccountSelection{ id : Some(*account.id()) }).await?;
                } else {
                    self.notify(Events::AccountSelection{ id : None }).await?;
                }
                Ok(())
            }

            /// Get currently selected account
            pub fn account(&self) -> Result<Arc<dyn Account>> {
                self.inner.selected_account.lock().unwrap().clone().ok_or_else(|| Error::AccountSelection)
            }



        }
    }

    /// Loads a wallet from storage. Accounts are not activated by this call.
    async fn open_impl(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        filename: Option<String>,
        args: WalletOpenArgs,
    ) -> Result<Option<Vec<AccountDescriptor>>> {
        // let _guard = self.inner.guard.lock().await;

        let filename = filename.or_else(|| self.settings().get(WalletSettings::Wallet));
        // let name = Some(make_filename(&name, &None));

        let was_open = self.is_open();

        self.store().open(wallet_secret, OpenArgs::new(filename)).await?;
        let wallet_name = self.store().descriptor();

        if was_open {
            self.notify(Events::WalletClose).await?;
        }

        // reset current state only after we have successfully opened another wallet
        self.reset(true).await?;

        let accounts: Option<Vec<Arc<dyn Account>>> = if args.load_account_descriptors() {
            let stored_accounts = self.inner.store.as_account_store().unwrap().iter(None).await?.try_collect::<Vec<_>>().await?;
            let stored_accounts = if !args.is_legacy_only() {
                stored_accounts
            } else {
                stored_accounts
                    .into_iter()
                    .filter(|(account_storage, _)| account_storage.kind.as_ref() == LEGACY_ACCOUNT_KIND)
                    .collect::<Vec<_>>()
            };
            Some(
                futures::stream::iter(stored_accounts.into_iter())
                    .then(|(account, meta)| try_load_account(self, account, meta))
                    .try_collect::<Vec<_>>()
                    // .try_collect::<Result<Vec<_>>>()
                    .await?,
            )
        } else {
            None
        };

        if let Some(accounts) = &accounts {
            for account in accounts.iter() {
                if let Ok(legacy_account) = account.clone().as_legacy_account() {
                    legacy_account.create_private_context(wallet_secret, None, None).await?;
                    log_info!("create_private_context, open_impl: receive_address: {:?}", account.receive_address());
                    self.legacy_accounts().insert(account.clone());
                }
            }
        }

        let account_descriptors = accounts
            .as_ref()
            .map(|accounts| accounts.iter().map(|account| account.descriptor()).collect::<Result<Vec<_>>>())
            .transpose()?;

        self.notify(Events::WalletOpen { wallet_descriptor: wallet_name, account_descriptors: account_descriptors.clone() }).await?;

        let hint = self.store().get_user_hint().await?;
        self.notify(Events::WalletHint { hint }).await?;

        Ok(account_descriptors)
    }

    /// Loads a wallet from storage. Accounts are not activated by this call.
    pub async fn open(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        filename: Option<String>,
        args: WalletOpenArgs,
        _guard: &WalletGuard<'_>,
    ) -> Result<Option<Vec<AccountDescriptor>>> {
        // This is a wrapper of open_impl() that catches errors and notifies the UI
        match self.open_impl(wallet_secret, filename, args).await {
            Ok(account_descriptors) => Ok(account_descriptors),
            Err(err) => {
                self.notify(Events::WalletError { message: err.to_string() }).await?;
                Err(err)
            }
        }
    }

    async fn activate_accounts_impl(self: &Arc<Wallet>, account_ids: Option<&[AccountId]>) -> Result<Vec<AccountId>> {
        // let _guard = self.inner.guard.lock().await;

        let stored_accounts = if let Some(ids) = account_ids {
            self.inner.store.as_account_store().unwrap().load_multiple(ids).await?
        } else {
            self.inner.store.as_account_store().unwrap().iter(None).await?.try_collect::<Vec<_>>().await?
        };

        let ids = stored_accounts.iter().map(|(account, _)| *account.id()).collect::<Vec<_>>();

        for (account_storage, meta) in stored_accounts.into_iter() {
            if account_storage.kind.as_ref() == LEGACY_ACCOUNT_KIND {
                let legacy_account = self
                    .legacy_accounts()
                    .get(account_storage.id())
                    .ok_or_else(|| Error::LegacyAccountNotInitialized)?
                    .clone()
                    .as_legacy_account()?;
                legacy_account.clone().start().await?;
                legacy_account.clear_private_context().await?;
            } else if self.active_accounts().get(account_storage.id()).is_none() {
                let account = try_load_account(self, account_storage, meta).await?;
                account.clone().start().await?;
            }
        }

        self.notify(Events::AccountActivation { ids: ids.clone() }).await?;

        Ok(ids)
    }

    /// Activates accounts (performs account address space counts, initializes balance tracking, etc.)
    pub async fn activate_accounts(self: &Arc<Wallet>, account_ids: Option<&[AccountId]>, _guard: &WalletGuard<'_>) -> Result<()> {
        // This is a wrapper of activate_accounts_impl() that catches errors and notifies the UI
        if let Err(err) = self.activate_accounts_impl(account_ids).await {
            self.notify(Events::WalletError { message: err.to_string() }).await?;
            Err(err)
        } else {
            Ok(())
        }
    }

    pub async fn deactivate_accounts(self: &Arc<Wallet>, ids: Option<&[AccountId]>, _guard: &WalletGuard<'_>) -> Result<()> {
        let _guard = self.inner.guard.lock().await;

        let (ids, futures) = if let Some(ids) = ids {
            let accounts =
                ids.iter().map(|id| self.active_accounts().get(id).ok_or(Error::AccountNotFound(*id))).collect::<Result<Vec<_>>>()?;
            (ids.to_vec(), accounts.into_iter().map(|account| account.stop()).collect::<Vec<_>>())
        } else {
            self.active_accounts().collect().iter().map(|account| (account.id(), account.clone().stop())).unzip()
        };

        join_all(futures).await.into_iter().collect::<Result<Vec<_>>>()?;
        self.notify(Events::AccountDeactivation { ids }).await?;

        Ok(())
    }

    pub async fn account_descriptors(self: Arc<Self>, _guard: &WalletGuard<'_>) -> Result<Vec<AccountDescriptor>> {
        // let _guard = self.inner.guard.lock().await;

        let iter = self.inner.store.as_account_store().unwrap().iter(None).await.unwrap();
        let wallet = self.clone();

        let stream = iter.then(move |stored| {
            let wallet = wallet.clone();

            async move {
                let (stored_account, stored_metadata) = stored.unwrap();
                if let Some(account) = wallet.legacy_accounts().get(&stored_account.id) {
                    account.descriptor()
                } else if let Some(account) = wallet.active_accounts().get(&stored_account.id) {
                    account.descriptor()
                } else {
                    try_load_account(&wallet, stored_account, stored_metadata).await?.descriptor()
                }
            }
        });

        stream.try_collect::<Vec<_>>().await
    }

    pub async fn get_prv_key_data(&self, wallet_secret: &Secret, id: &PrvKeyDataId) -> Result<Option<PrvKeyData>> {
        self.inner.store.as_prv_key_data_store()?.load_key_data(wallet_secret, id).await
    }

    pub async fn get_prv_key_info(&self, account: &Arc<dyn Account>) -> Result<Option<Arc<PrvKeyDataInfo>>> {
        self.inner.store.as_prv_key_data_store()?.load_key_info(account.prv_key_data_id()?).await
    }

    pub async fn is_account_key_encrypted(&self, account: &Arc<dyn Account>) -> Result<Option<bool>> {
        let store = self.inner.store.as_prv_key_data_store()?;
        let prv_key_data_ids = account.to_storage()?.prv_key_data_ids;
        let mut any_seen = false;
        let mut any_encrypted = false;
        for id in &prv_key_data_ids {
            any_seen = true;
            if let Some(info) = store.load_key_info(&id).await?
                && info.is_encrypted()
            {
                any_encrypted = true;
                break;
            }
        }
        if any_seen { Ok(Some(any_encrypted)) } else { Ok(None) }
    }

    pub fn try_wrpc_client(&self) -> Option<Arc<KaspaRpcClient>> {
        self.try_rpc_api().and_then(|api| api.clone().downcast_arc::<KaspaRpcClient>().ok())
    }

    pub fn wrpc_client(&self) -> Arc<KaspaRpcClient> {
        self.try_rpc_api().and_then(|api| api.clone().downcast_arc::<KaspaRpcClient>().ok()).unwrap()
    }

    pub fn rpc_api(&self) -> Arc<DynRpcApi> {
        self.utxo_processor().rpc_api()
    }

    pub fn try_rpc_api(&self) -> Option<Arc<DynRpcApi>> {
        self.utxo_processor().try_rpc_api()
    }

    pub fn rpc_ctl(&self) -> RpcCtl {
        self.utxo_processor().rpc_ctl()
    }

    pub fn try_rpc_ctl(&self) -> Option<RpcCtl> {
        self.utxo_processor().try_rpc_ctl()
    }

    pub fn has_rpc(&self) -> bool {
        self.utxo_processor().has_rpc()
    }

    pub async fn bind_rpc(self: &Arc<Self>, rpc: Option<Rpc>) -> Result<()> {
        self.utxo_processor().bind_rpc(rpc).await?;
        Ok(())
    }

    pub fn as_api(self: &Arc<Self>) -> Arc<dyn WalletApi> {
        self.clone()
    }

    pub fn to_api(self) -> Arc<dyn WalletApi> {
        Arc::new(self)
    }

    pub fn multiplexer(&self) -> &Multiplexer<Box<Events>> {
        &self.inner.multiplexer
    }

    pub(crate) fn wallet_bus(&self) -> &Channel<WalletBusMessage> {
        &self.inner.wallet_bus
    }

    pub fn settings(&self) -> &SettingsStore<WalletSettings> {
        &self.inner.settings
    }

    pub fn current_daa_score(&self) -> Option<u64> {
        self.utxo_processor().current_daa_score()
    }

    pub async fn load_settings(&self) -> Result<()> {
        self.settings().try_load().await?;

        let settings = self.settings();

        if let Some(network_id) = settings.get(WalletSettings::Network) {
            self.set_network_id(&network_id).unwrap_or_else(|_| log_error!("Unable to select network type: `{}`", network_id));
        }

        if let Some(url) = settings.get::<String>(WalletSettings::Server)
            && let Some(wrpc_client) = self.try_wrpc_client()
        {
            wrpc_client.set_url(Some(url.as_str())).unwrap_or_else(|_| log_error!("Unable to set rpc url: `{}`", url));
        }

        Ok(())
    }

    // intended for starting async management tasks
    pub async fn start(self: &Arc<Self>) -> Result<()> {
        // self.load_settings().await.unwrap_or_else(|_| log_error!("Unable to load settings, discarding..."));

        // internal event loop
        self.start_task().await?;
        self.utxo_processor().start().await?;
        // rpc services (notifier)
        if let Some(rpc_client) = self.try_wrpc_client() {
            rpc_client.start().await?;
        }

        Ok(())
    }

    // intended for stopping async management task
    pub async fn stop(&self) -> Result<()> {
        self.utxo_processor().stop().await?;
        self.stop_task().await?;
        Ok(())
    }

    pub fn listener_id(&self) -> Result<ListenerId> {
        self.inner.listener_id.lock().unwrap().ok_or(Error::ListenerId)
    }

    pub async fn get_info(&self) -> Result<String> {
        let v = self.rpc_api().get_info().await?;
        Ok(format!("{v:#?}").replace('\n', "\r\n"))
    }

    pub async fn subscribe_daa_score(&self) -> Result<()> {
        self.rpc_api().start_notify(self.listener_id()?, Scope::VirtualDaaScoreChanged(VirtualDaaScoreChangedScope {})).await?;
        Ok(())
    }

    pub async fn unsubscribe_daa_score(&self) -> Result<()> {
        self.rpc_api().stop_notify(self.listener_id()?, Scope::VirtualDaaScoreChanged(VirtualDaaScoreChangedScope {})).await?;
        Ok(())
    }

    pub async fn broadcast(&self) -> Result<()> {
        Ok(())
    }

    pub fn set_network_id(&self, network_id: &NetworkId) -> Result<()> {
        if self.is_connected() {
            return Err(Error::NetworkTypeConnected);
        }
        self.utxo_processor().set_network_id(network_id);

        if let Some(wrpc_client) = self.try_wrpc_client() {
            wrpc_client.set_network_id(network_id)?;
        }
        Ok(())
    }

    pub fn network_id(&self) -> Result<NetworkId> {
        self.utxo_processor().network_id()
    }

    pub fn address_prefix(&self) -> Result<kaspa_addresses::Prefix> {
        Ok(self.network_id()?.into())
    }

    pub fn default_port(&self) -> Result<Option<u16>> {
        let network_type = self.network_id()?;
        if let Some(wrpc_client) = self.try_wrpc_client() {
            let port = match wrpc_client.encoding() {
                WrpcEncoding::Borsh => network_type.default_borsh_rpc_port(),
                WrpcEncoding::SerdeJson => network_type.default_json_rpc_port(),
            };
            Ok(Some(port))
        } else {
            Ok(None)
        }
    }

    pub async fn create_account(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        account_create_args: AccountCreateArgs,
        notify: bool,
        _guard: &WalletGuard<'_>,
    ) -> Result<Arc<dyn Account>> {
        let account = match account_create_args {
            AccountCreateArgs::Bip32 { prv_key_data_args, account_args } => {
                let PrvKeyDataArgs { prv_key_data_id, payment_secret } = prv_key_data_args;
                self.create_account_bip32(wallet_secret, prv_key_data_id, payment_secret.as_ref(), account_args).await?
            }
            AccountCreateArgs::Legacy { prv_key_data_id, account_name } => {
                self.create_account_legacy(wallet_secret, prv_key_data_id, account_name).await?
            }
            AccountCreateArgs::Multisig { prv_key_data_args, additional_xpub_keys, name, minimum_signatures } => {
                self.create_account_multisig(wallet_secret, prv_key_data_args, additional_xpub_keys, name, minimum_signatures).await?
            }
            AccountCreateArgs::Bip32Watch { account_args } => self.create_account_bip32_watch(wallet_secret, account_args).await?,
            AccountCreateArgs::Keypair { prv_key_data_id, account_name, ecdsa } => {
                self.create_account_keypair(wallet_secret, None, prv_key_data_id, account_name, ecdsa).await?
            }
        };

        if notify {
            let account_descriptor = account.descriptor()?;
            self.notify(Events::AccountCreate { account_descriptor }).await?;
        }

        Ok(account)
    }

    pub async fn create_account_multisig(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        prv_key_data_args: Vec<PrvKeyDataArgs>,
        xpub_keys: Vec<String>,
        account_name: Option<String>,
        minimum_signatures: u16,
    ) -> Result<Arc<dyn Account>> {
        let account_store = self.inner.store.clone().as_account_store()?;
        let wallet_network = self.network_id()?.network_type();

        // Derive an xpub per local seed; the cosigner_index and the
        // prv_key_data_ids vector are populated only when the operator
        // contributes one or more local seeds. The vectors are empty
        // for an all-external-cosigner (watch-only) multisig.
        let mut generated_xpubs = Vec::with_capacity(prv_key_data_args.len());
        let mut prv_key_data_ids = Vec::with_capacity(prv_key_data_args.len());
        for prv_key_data_arg in prv_key_data_args.into_iter() {
            let PrvKeyDataArgs { prv_key_data_id, payment_secret } = prv_key_data_arg;
            let prv_key_data = self
                .inner
                .store
                .as_prv_key_data_store()?
                .load_key_data(wallet_secret, &prv_key_data_id)
                .await?
                .ok_or_else(|| Error::PrivateKeyNotFound(prv_key_data_id))?;
            let xpub_key = prv_key_data.create_xpub(payment_secret.as_ref(), MULTISIG_ACCOUNT_KIND.into(), 0).await?; // todo it can be done concurrently
            generated_xpubs.push(xpub_key.to_string(Some(KeyPrefix::XPUB)));
            prv_key_data_ids.push(prv_key_data_id);
        }
        generated_xpubs.sort_unstable();

        // Unconditional construction-time guard set so the same checks
        // (cross-network xpub, count cap, threshold bounds, redeem-script
        // element-size, duplicate xpub) apply to both the local-seed-bearing
        // and the all-external-cosigner paths; otherwise the watch-only
        // path persists multisig accounts that the consensus engine would
        // reject at first spend.
        let xpub_keys = normalize_and_merge_xpubs(xpub_keys, &generated_xpubs, minimum_signatures, wallet_network)?;

        let (prv_key_data_ids_opt, min_cosigner_index) = if prv_key_data_ids.is_empty() {
            (None, None)
        } else {
            let mci =
                generated_xpubs.first().and_then(|first_generated| xpub_keys.binary_search(first_generated).ok()).map(|v| v as u8);
            (Some(Arc::new(prv_key_data_ids)), mci)
        };

        let xpub_keys = xpub_keys
            .into_iter()
            .map(|xpub_key| {
                ExtendedPublicKeySecp256k1::from_str(&xpub_key).map_err(|err| Error::InvalidExtendedPublicKey(xpub_key, err))
            })
            .collect::<Result<Vec<_>>>()?;

        let account: Arc<dyn Account> = Arc::new(
            multisig::MultiSig::try_new(
                self,
                account_name,
                Arc::new(xpub_keys),
                prv_key_data_ids_opt,
                min_cosigner_index,
                minimum_signatures,
                false,
            )
            .await?,
        );

        if account_store.load_single(account.id()).await?.is_some() {
            return Err(Error::AccountAlreadyExists(*account.id()));
        }

        self.inner.store.clone().as_account_store()?.store_single(&account.to_storage()?, None).await?;
        self.inner.store.commit(wallet_secret).await?;

        Ok(account)
    }

    pub async fn create_account_bip32(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        prv_key_data_id: PrvKeyDataId,
        payment_secret: Option<&Secret>,
        account_args: AccountCreateArgsBip32,
    ) -> Result<Arc<dyn Account>> {
        let account_store = self.inner.store.clone().as_account_store()?;

        let prv_key_data = self
            .inner
            .store
            .as_prv_key_data_store()?
            .load_key_data(wallet_secret, &prv_key_data_id)
            .await?
            .ok_or_else(|| Error::PrivateKeyNotFound(prv_key_data_id))?;

        let AccountCreateArgsBip32 { account_name, account_index } = account_args;

        let account_index = if let Some(account_index) = account_index {
            account_index
        } else {
            let accounts = account_store.clone().iter(Some(prv_key_data_id)).await?.collect::<Vec<_>>().await;

            accounts
                .into_iter()
                .filter(|a| a.as_ref().ok().and_then(|(a, _)| (a.kind == BIP32_ACCOUNT_KIND).then_some(true)).unwrap_or(false))
                .collect::<Vec<_>>()
                .len() as u64
        };

        let xpub_key = prv_key_data.create_xpub(payment_secret, BIP32_ACCOUNT_KIND.into(), account_index).await?;
        let xpub_keys = Arc::new(vec![xpub_key]);

        let account: Arc<dyn Account> =
            Arc::new(bip32::Bip32::try_new(self, account_name, prv_key_data.id, account_index, xpub_keys, false).await?);

        if account_store.load_single(account.id()).await?.is_some() {
            return Err(Error::AccountAlreadyExists(*account.id()));
        }

        self.inner.store.clone().as_account_store()?.store_single(&account.to_storage()?, None).await?;
        self.inner.store.commit(wallet_secret).await?;

        Ok(account)
    }

    pub async fn create_account_bip32_watch(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        account_args: AccountCreateArgsBip32Watch,
    ) -> Result<Arc<dyn Account>> {
        let account_store = self.inner.store.clone().as_account_store()?;

        let AccountCreateArgsBip32Watch { account_name, xpub_keys } = account_args;

        let xpub_keys = Arc::new(
            xpub_keys
                .into_iter()
                .map(|xpub_key| {
                    ExtendedPublicKeySecp256k1::from_str(&xpub_key).map_err(|err| Error::InvalidExtendedPublicKey(xpub_key, err))
                })
                .collect::<Result<Vec<_>>>()?,
        );

        let account: Arc<dyn Account> = Arc::new(bip32watch::Bip32Watch::try_new(self, account_name, xpub_keys, false).await?);

        if account_store.load_single(account.id()).await?.is_some() {
            return Err(Error::AccountAlreadyExists(*account.id()));
        }

        self.inner.store.clone().as_account_store()?.store_single(&account.to_storage()?, None).await?;
        self.inner.store.commit(wallet_secret).await?;

        Ok(account)
    }

    async fn create_account_legacy(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        prv_key_data_id: PrvKeyDataId,
        account_name: Option<String>,
    ) -> Result<Arc<dyn Account>> {
        let account_store = self.inner.store.clone().as_account_store()?;

        let prv_key_data = self
            .inner
            .store
            .as_prv_key_data_store()?
            .load_key_data(wallet_secret, &prv_key_data_id)
            .await?
            .ok_or_else(|| Error::PrivateKeyNotFound(prv_key_data_id))?;

        let account: Arc<dyn Account> = Arc::new(legacy::Legacy::try_new(self, account_name, prv_key_data.id).await?);
        if let Ok(legacy_account) = account.clone().as_legacy_account() {
            legacy_account.create_private_context(wallet_secret, None, None).await?;
            log_info!("create_private_context: create_account_legacy, receive_address: {:?}", account.receive_address());
            self.legacy_accounts().insert(account.clone());
            //legacy_account.clear_private_context().await?;
        }

        if account_store.load_single(account.id()).await?.is_some() {
            return Err(Error::AccountAlreadyExists(*account.id()));
        }

        self.inner.store.clone().as_account_store()?.store_single(&account.to_storage()?, None).await?;
        self.inner.store.commit(wallet_secret).await?;

        Ok(account)
    }

    pub async fn create_account_keypair(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        payment_secret: Option<&Secret>,
        prv_key_data_id: PrvKeyDataId,
        account_name: Option<String>,
        ecdsa: bool,
    ) -> Result<Arc<dyn Account>> {
        let account_store = self.inner.store.clone().as_account_store()?;

        let prv_key_data = self
            .inner
            .store
            .as_prv_key_data_store()?
            .load_key_data(wallet_secret, &prv_key_data_id)
            .await?
            .ok_or_else(|| Error::PrivateKeyNotFound(prv_key_data_id))?;

        let secret_key = prv_key_data
            .as_secret_key(payment_secret)
            .map_err(|_| Error::custom("Invalid private key"))?
            .ok_or(Error::custom("Sectet key is required"))?;

        let secp = secp256k1::Secp256k1::new();
        let public_key = secret_key.public_key(&secp);
        let prv_key_data_id = prv_key_data.id;
        let account: Arc<dyn Account> =
            Arc::new(keypair::Keypair::try_new(self, account_name, public_key, prv_key_data_id, ecdsa).await?);

        if account_store.load_single(account.id()).await?.is_some() {
            return Err(Error::AccountAlreadyExists(*account.id()));
        }

        self.inner.store.clone().as_account_store()?.store_single(&account.to_storage()?, None).await?;
        self.inner.store.commit(wallet_secret).await?;

        Ok(account)
    }

    pub async fn create_wallet(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        args: WalletCreateArgs,
    ) -> Result<(WalletDescriptor, StorageDescriptor)> {
        self.close().await?;

        let wallet_descriptor = self.inner.store.create(wallet_secret, args.into()).await?;
        let storage_descriptor = self.inner.store.location()?;
        self.inner.store.commit(wallet_secret).await?;

        self.notify(Events::WalletCreate {
            wallet_descriptor: wallet_descriptor.clone(),
            storage_descriptor: storage_descriptor.clone(),
        })
        .await?;

        Ok((wallet_descriptor, storage_descriptor))
    }

    pub async fn create_prv_key_data(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        prv_key_data_create_args: PrvKeyDataCreateArgs,
    ) -> Result<PrvKeyDataId> {
        let PrvKeyDataCreateArgs { secret, payment_secret, kind, name } = prv_key_data_create_args;
        let prv_key_data = match kind {
            PrvKeyDataVariantKind::Mnemonic => {
                let mnemonic = Mnemonic::new(secret.as_str()?, Language::default())?;
                PrvKeyData::try_from_mnemonic(mnemonic.clone(), payment_secret.as_ref(), self.store().encryption_kind()?, name)?
            }
            PrvKeyDataVariantKind::SecretKey => {
                //let secp = secp256k1::Secp256k1::new();
                let secret_key = secp256k1::SecretKey::from_slice(secret.as_ref())?;
                //let public_key = secret_key.public_key(&secp);
                //log_info!("public_key: {}", public_key.to_string());
                PrvKeyData::try_from_secret_key(secret_key, payment_secret.as_ref(), self.store().encryption_kind()?, name)?
            }
            _ => {
                return Err(Error::Custom("Invalid prv key data kind, supported types are Mnemonic and SecretKey".to_string()));
            }
        };

        let prv_key_data_info = PrvKeyDataInfo::from(prv_key_data.as_ref());
        let prv_key_data_id = prv_key_data.id;
        let prv_key_data_store = self.inner.store.as_prv_key_data_store()?;
        prv_key_data_store.store(wallet_secret, prv_key_data).await?;
        self.inner.store.commit(wallet_secret).await?;

        self.notify(Events::PrvKeyDataCreate { prv_key_data_info }).await?;

        Ok(prv_key_data_id)
    }

    pub async fn create_wallet_with_accounts(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        wallet_args: WalletCreateArgs,
        account_name: Option<String>,
        account_kind: Option<AccountKind>,
        mnemonic_phrase_word_count: WordCount,
        payment_secret: Option<Secret>,
    ) -> Result<(WalletDescriptor, StorageDescriptor, Mnemonic, Arc<dyn Account>)> {
        self.close().await?;

        let encryption_kind = wallet_args.encryption_kind;
        let wallet_descriptor = self.inner.store.create(wallet_secret, wallet_args.into()).await?;
        let storage_descriptor = self.inner.store.location()?;
        let mnemonic = Mnemonic::random(mnemonic_phrase_word_count, Default::default())?;
        let account_index = 0;
        let prv_key_data = PrvKeyData::try_from_mnemonic(mnemonic.clone(), payment_secret.as_ref(), encryption_kind, None)?;
        let xpub_key = prv_key_data
            .create_xpub(payment_secret.as_ref(), account_kind.unwrap_or(BIP32_ACCOUNT_KIND.into()), account_index)
            .await?;
        let xpub_keys = Arc::new(vec![xpub_key]);

        let account: Arc<dyn Account> =
            Arc::new(bip32::Bip32::try_new(self, account_name, prv_key_data.id, account_index, xpub_keys, false).await?);

        let prv_key_data_store = self.inner.store.as_prv_key_data_store()?;
        prv_key_data_store.store(wallet_secret, prv_key_data).await?;
        self.inner.store.clone().as_account_store()?.store_single(&account.to_storage()?, None).await?;
        self.inner.store.commit(wallet_secret).await?;

        self.select(Some(&account)).await?;
        Ok((wallet_descriptor, storage_descriptor, mnemonic, account))
    }

    pub async fn get_account_by_id(
        self: &Arc<Self>,
        account_id: &AccountId,
        _guard: &WalletGuard<'_>,
    ) -> Result<Option<Arc<dyn Account>>> {
        let _guard = self.inner.account_guard.lock().await;

        if let Some(account) = self.active_accounts().get(account_id) {
            Ok(Some(account.clone()))
        } else {
            let account_storage = self.inner.store.as_account_store()?;
            let stored = account_storage.load_single(account_id).await?;
            if let Some((stored_account, stored_metadata)) = stored {
                let account = try_load_account(self, stored_account, stored_metadata).await?;
                Ok(Some(account))
            } else {
                Ok(None)
            }
        }
    }

    pub async fn notify(&self, event: Events) -> Result<()> {
        self.multiplexer()
            .try_broadcast(Box::new(event))
            .map_err(|_| Error::Custom("multiplexer channel error during update_balance".to_string()))?;
        Ok(())
    }

    pub fn is_synced(&self) -> bool {
        self.utxo_processor().is_synced()
    }

    pub fn is_connected(&self) -> bool {
        self.utxo_processor().is_connected()
    }

    pub(crate) async fn handle_discovery(&self, record: TransactionRecord) -> Result<()> {
        let transaction_store = self.store().as_transaction_record_store()?;

        if let Err(_err) = transaction_store.load_single(record.binding(), &self.network_id()?, record.id()).await {
            let transaction_daa_score = record.block_daa_score();
            match self.rpc_api().get_daa_score_timestamp_estimate(vec![transaction_daa_score]).await {
                Ok(timestamps) => {
                    if let Some(timestamp) = timestamps.first() {
                        let mut record = record.clone();
                        record.set_unixtime(*timestamp);

                        transaction_store.store(&[&record]).await?;

                        self.notify(Events::Discovery { record }).await?;
                    } else {
                        self.notify(Events::Error {
                            message: format!(
                                "Unable to obtain DAA to unixtime for DAA {transaction_daa_score}, timestamp data is empty"
                            ),
                        })
                        .await?;
                    }
                }
                Err(err) => {
                    self.notify(Events::Error { message: format!("Unable to resolve DAA to unixtime: {err}") }).await?;
                }
            }
        }

        Ok(())
    }

    async fn handle_wallet_bus(self: &Arc<Self>, message: WalletBusMessage) -> Result<()> {
        match message {
            WalletBusMessage::Discovery { record } => {
                self.handle_discovery(record).await?;
            }
        }
        Ok(())
    }

    async fn handle_event(self: &Arc<Self>, event: Box<Events>) -> Result<()> {
        match &*event {
            Events::Pending { record } | Events::Maturity { record } | Events::Reorg { record } => {
                if !record.is_change() {
                    self.store().as_transaction_record_store()?.store(&[record]).await?;
                }
            }

            _ => {}
        }

        Ok(())
    }

    async fn start_task(self: &Arc<Self>) -> Result<()> {
        let this = self.clone();
        let task_ctl_receiver = self.inner.task_ctl.request.receiver.clone();
        let task_ctl_sender = self.inner.task_ctl.response.sender.clone();
        let events = self.multiplexer().channel();
        let wallet_bus_receiver = self.wallet_bus().receiver.clone();

        // let this_clone = self.clone();
        // spawn(async move {
        //     loop {
        //         log_info!("Wallet broadcasting ping...");
        //         this_clone.notify(Events::WalletPing).await.expect("Wallet::start_task() `notify` error");
        //         sleep(Duration::from_secs(5)).await;
        //     }
        // });

        spawn(async move {
            loop {
                select! {
                    _ = task_ctl_receiver.recv().fuse() => {
                        break;
                    },

                    msg = events.receiver.recv().fuse() => {
                        match msg {
                            Ok(event) => {
                                this.handle_event(event).await.unwrap_or_else(|e| log_error!("Wallet::handle_event() error: {}", e));
                            },
                            Err(err) => {
                                log_error!("Wallet: error while receiving multiplexer message: {err}");
                                log_error!("Suspending Wallet processing...");

                                break;
                            }
                        }
                    },

                    msg = wallet_bus_receiver.recv().fuse() => {
                        match msg {
                            Ok(message) => {
                                this.handle_wallet_bus(message).await.unwrap_or_else(|e| log_error!("Wallet::handle_wallet_bus() error: {}", e));
                            },
                            Err(err) => {
                                log_error!("Wallet: error while receiving wallet bus message: {err}");
                                log_error!("Suspending Wallet processing...");

                                break;
                            }
                        }
                    }
                }
            }

            task_ctl_sender.send(()).await.unwrap();
        });
        Ok(())
    }

    async fn stop_task(&self) -> Result<()> {
        self.inner.task_ctl.signal(()).await.expect("Wallet::stop_task() `signal` error");
        Ok(())
    }

    pub fn enable_metrics_kinds(&self, kinds: &[MetricsUpdateKind]) {
        self.utxo_processor().enable_metrics_kinds(kinds);
    }

    pub async fn start_metrics(&self) -> Result<()> {
        self.utxo_processor().start_metrics().await?;
        Ok(())
    }

    pub async fn stop_metrics(&self) -> Result<()> {
        self.utxo_processor().stop_metrics().await?;
        Ok(())
    }

    pub fn is_open(&self) -> bool {
        self.inner.store.is_open()
    }

    pub fn location(&self) -> Result<StorageDescriptor> {
        self.inner.store.location()
    }

    pub async fn exists(&self, name: Option<&str>) -> Result<bool> {
        self.inner.store.exists(name).await
    }

    pub async fn keys(&self) -> Result<impl Stream<Item = Result<Arc<PrvKeyDataInfo>>>> {
        self.inner.store.as_prv_key_data_store()?.iter().await
    }

    pub async fn find_accounts_by_name_or_id(&self, pat: &str) -> Result<Vec<Arc<dyn Account>>> {
        let active_accounts = self.active_accounts().inner().values().cloned().collect::<Vec<_>>();
        let matches = active_accounts
            .into_iter()
            .filter(|account| {
                account.name().map(|name| name.starts_with(pat)).unwrap_or(false) || account.id().to_hex().starts_with(pat)
            })
            .collect::<Vec<_>>();
        Ok(matches)
    }

    pub async fn accounts(
        self: &Arc<Self>,
        filter: Option<PrvKeyDataId>,
        _guard: &WalletGuard<'_>,
    ) -> Result<impl Stream<Item = Result<Arc<dyn Account>>>> {
        let iter = self.inner.store.as_account_store().unwrap().iter(filter).await.unwrap();
        let wallet = self.clone();

        let stream = iter.then(move |stored| {
            let wallet = wallet.clone();

            async move {
                let (stored_account, stored_metadata) = stored.unwrap();
                if let Some(account) = wallet.legacy_accounts().get(&stored_account.id) {
                    if !wallet.active_accounts().contains(account.id()) {
                        account.clone().start().await?;
                    }
                    Ok(account)
                } else if let Some(account) = wallet.active_accounts().get(&stored_account.id) {
                    Ok(account)
                } else {
                    let account = try_load_account(&wallet, stored_account, stored_metadata).await?;
                    account.clone().start().await?;
                    Ok(account)
                }
            }
        });

        Ok(Box::pin(stream))
    }

    // TODO - remove these comments (these functions are a part of
    // a major refactoring and are temporarily kept here for reference)

    // pub async fn initialize_legacy_accounts(
    //     self: &Arc<Self>,
    //     filter: Option<PrvKeyDataId>,
    //     secret: Secret,
    // ) -> Result<()> {
    //     let mut iter = self.inner.store.as_account_store().unwrap().iter(filter).await.unwrap();
    //     let wallet = self.clone();

    //     while let Some((stored_account, stored_metadata)) = iter.try_next().await? {
    //         if matches!(stored_account.data, AccountData::Legacy { .. }) {

    //             let account = try_from_storage(&wallet, stored_account, stored_metadata).await?;

    //                 account.clone().initialize_private_data(secret.clone(), None, None).await?;
    //                 wallet.legacy_accounts().insert(account.clone());
    //                 // account.clone().start().await?;

    //             // if is_legacy {
    //                 // let derivation = account.clone().as_derivation_capable()?.derivation();
    //                 // let m = derivation.receive_address_manager();
    //                 // m.get_range(0..(m.index() + CACHE_ADDRESS_OFFSET))?;
    //                 // let m = derivation.change_address_manager();
    //                 // m.get_range(0..(m.index() + CACHE_ADDRESS_OFFSET))?;

    //                 // - TODO - consider two-phase approach
    //                 // account.clone().clear_private_data().await?;
    //             // }
    //         }
    //     }

    //     Ok(())

    // // let stream = iter.then(move |stored| {
    //     let wallet = wallet.clone();
    //     let secret = secret.clone();

    //     // async move {
    //         let (stored_account, stored_metadata) = stored.unwrap();
    //         // if let Some(account) = wallet.active_accounts().get(&stored_account.id) {
    //             // Ok(account)
    //         // } else {
    //             if matches!(stored_account.data, AccountData::Legacy { .. }) {

    //                 let account = try_from_storage(&wallet, stored_account, stored_metadata).await?;

    //                 // if is_legacy {
    //                     account.clone().initialize_private_data(secret, None, None).await?;
    //                     wallet.legacy_accounts().insert(account.clone());
    //                 // }

    //                 // account.clone().start().await?;

    //                 // if is_legacy {
    //                     let derivation = account.clone().as_derivation_capable()?.derivation();
    //                     let m = derivation.receive_address_manager();
    //                     m.get_range(0..(m.index() + CACHE_ADDRESS_OFFSET))?;
    //                     let m = derivation.change_address_manager();
    //                     m.get_range(0..(m.index() + CACHE_ADDRESS_OFFSET))?;
    //                     account.clone().clear_private_data().await?;
    //                 // }
    //             }

    // Ok(account)
    // }
    // }
    // });
    // Ok(Box::pin(stream))
    // }

    // pub async fn initialize_accounts(
    //     self: &Arc<Self>,
    //     filter: Option<PrvKeyDataId>,
    //     secret: Secret,
    // ) -> Result<impl Stream<Item = Result<Arc<dyn Account>>>> {
    //     let iter = self.inner.store.as_account_store().unwrap().iter(filter).await.unwrap();
    //     let wallet = self.clone();

    //     let stream = iter.then(move |stored| {
    //         let wallet = wallet.clone();
    //         let secret = secret.clone();

    //         async move {
    //             let (stored_account, stored_metadata) = stored.unwrap();
    //             if let Some(account) = wallet.active_accounts().get(&stored_account.id) {
    //                 Ok(account)
    //             } else {
    //                 let is_legacy = matches!(stored_account.data, AccountData::Legacy { .. });
    //                 let account = try_from_storage(&wallet, stored_account, stored_metadata).await?;

    //                 if is_legacy {
    //                     account.clone().initialize_private_data(secret, None, None).await?;
    //                     wallet.legacy_accounts().insert(account.clone());
    //                 }

    //                 // account.clone().start().await?;

    //                 if is_legacy {
    //                     let derivation = account.clone().as_derivation_capable()?.derivation();
    //                     let m = derivation.receive_address_manager();
    //                     m.get_range(0..(m.index() + CACHE_ADDRESS_OFFSET))?;
    //                     let m = derivation.change_address_manager();
    //                     m.get_range(0..(m.index() + CACHE_ADDRESS_OFFSET))?;
    //                     account.clone().clear_private_data().await?;
    //                 }

    //                 Ok(account)
    //             }
    //         }
    //     });

    //     Ok(Box::pin(stream))
    // }

    pub async fn import_kaspawallet_golang_single_v1<T: AsRef<[u8]>>(
        self: &Arc<Wallet>,
        import_secret: &Secret,
        wallet_secret: &Secret,
        file: SingleWalletFileV1<'_, T>,
    ) -> Result<Arc<dyn Account>> {
        if file.ecdsa {
            return Err(Error::Custom("ecdsa currently not suppoerted".to_owned()));
            // todo import_with_mnemonic should accept both
        }
        let mnemonic = decrypt_mnemonic(SingleWalletFileV1::<T>::NUM_THREADS, file.encrypted_mnemonic, import_secret.as_ref())?;
        let mnemonic = Mnemonic::new(mnemonic.trim(), Language::English)?;
        let prv_key_data = storage::PrvKeyData::try_new_from_mnemonic(mnemonic.clone(), None, self.store().encryption_kind()?)?;
        let prefix = file.xpublic_key.split_at(kaspa_bip32::Prefix::LENGTH).0;
        let prefix = kaspa_bip32::Prefix::try_from(prefix)?;

        if prv_key_data.create_xpub(None, BIP32_ACCOUNT_KIND.into(), 0).await?.to_string(Some(prefix)) != file.xpublic_key {
            return Err(Custom("imported xpub does not equal derived one".to_owned()));
        }
        self.import_with_mnemonic(wallet_secret, None, mnemonic, BIP32_ACCOUNT_KIND.into()).await
    }

    pub async fn import_kaspawallet_golang_single_v0<T: AsRef<[u8]>>(
        self: &Arc<Wallet>,
        import_secret: &Secret,
        wallet_secret: &Secret,
        file: SingleWalletFileV0<'_, T>,
    ) -> Result<Arc<dyn Account>> {
        if file.ecdsa {
            return Err(Error::Custom("ecdsa currently not suppoerted".to_owned()));
            // todo import_with_mnemonic should accept both
        }
        let mnemonic = decrypt_mnemonic(file.num_threads, file.encrypted_mnemonic, import_secret.as_ref())?;
        let mnemonic = Mnemonic::new(mnemonic.trim(), Language::English)?;
        let prv_key_data = storage::PrvKeyData::try_new_from_mnemonic(mnemonic.clone(), None, self.store().encryption_kind()?)?;
        let prefix = file.xpublic_key.split_at(kaspa_bip32::Prefix::LENGTH).0;
        let prefix = kaspa_bip32::Prefix::try_from(prefix)?;
        if prv_key_data.create_xpub(None, BIP32_ACCOUNT_KIND.into(), 0).await.unwrap().to_string(Some(prefix)) != file.xpublic_key {
            return Err(Custom("imported xpub does not equal derived one".to_owned()));
        }
        self.import_with_mnemonic(wallet_secret, None, mnemonic, BIP32_ACCOUNT_KIND.into()).await
    }

    pub async fn import_kaspawallet_golang_multisig_v0<T: AsRef<[u8]>>(
        self: &Arc<Wallet>,
        import_secret: &Secret,
        wallet_secret: &Secret,
        file: MultisigWalletFileV0<'_, T>,
    ) -> Result<Arc<dyn Account>> {
        if file.ecdsa {
            return Err(Error::Custom("ecdsa currently not suppoerted".to_owned()));
            // todo import_with_mnemonic should accept both
        }
        let Some(first_pub_key) = file.xpublic_keys.first() else {
            return Err(Error::Custom("no public keys".to_owned()));
        };
        let prefix = first_pub_key.split_at(kaspa_bip32::Prefix::LENGTH).0;
        let prefix = kaspa_bip32::Prefix::try_from(prefix)?;

        let mnemonics_and_secrets: Vec<(Mnemonic, Option<Secret>)> = file
            .encrypted_mnemonics
            .into_iter()
            .map(|mnemonic| {
                decrypt_mnemonic(file.num_threads, mnemonic, import_secret.as_ref())
                    .and_then(|decrypted| Mnemonic::new(decrypted.trim(), Language::English).map_err(Error::from))
            })
            .map(|r| r.map(|m| (m, <Option<Secret>>::None)))
            .collect::<Result<Vec<(Mnemonic, Option<Secret>)>>>()?;

        let mut all_pub_keys = file.xpublic_keys;
        all_pub_keys.sort_unstable();

        let mut pubkeys_from_mnemonics = Vec::with_capacity(mnemonics_and_secrets.len());
        for (mnemonic, _) in mnemonics_and_secrets.iter() {
            let priv_key = storage::PrvKeyData::try_new_from_mnemonic(mnemonic.clone(), None, self.store().encryption_kind()?)?;
            let xpub_key = priv_key.create_xpub(None, BIP32_ACCOUNT_KIND.into(), 0).await.unwrap().to_string(Some(prefix));
            pubkeys_from_mnemonics.push(xpub_key);
        }
        pubkeys_from_mnemonics.sort_unstable();
        all_pub_keys.retain(|v| pubkeys_from_mnemonics.binary_search_by_key(v, |xpub| xpub.as_str()).is_err());
        let additional_pub_keys = all_pub_keys.into_iter().map(String::from).collect();
        self.import_multisig_with_mnemonic(wallet_secret, mnemonics_and_secrets, file.required_signatures, additional_pub_keys).await
    }

    pub async fn import_kaspawallet_golang_multisig_v1<T: AsRef<[u8]>>(
        self: &Arc<Wallet>,
        import_secret: &Secret,
        wallet_secret: &Secret,
        file: MultisigWalletFileV1<'_, T>,
    ) -> Result<Arc<dyn Account>> {
        if file.ecdsa {
            return Err(Error::Custom("ecdsa currently not suppoerted".to_owned()));
            // todo import_with_mnemonic should accept both
        }
        let Some(first_pub_key) = file.xpublic_keys.first() else {
            return Err(Error::Custom("no public keys".to_owned()));
        };
        let prefix = first_pub_key.split_at(kaspa_bip32::Prefix::LENGTH).0;
        let prefix = kaspa_bip32::Prefix::try_from(prefix)?;

        let mnemonics_and_secrets: Vec<(Mnemonic, Option<Secret>)> = file
            .encrypted_mnemonics
            .into_iter()
            .map(|mnemonic| {
                decrypt_mnemonic(MultisigWalletFileV1::<T>::NUM_THREADS, mnemonic, import_secret.as_ref())
                    .and_then(|decrypted| Mnemonic::new(decrypted.trim(), Language::English).map_err(Error::from))
            })
            .map(|r| r.map(|m| (m, <Option<Secret>>::None)))
            .collect::<Result<Vec<(Mnemonic, Option<Secret>)>>>()?;

        let mut all_pub_keys = file.xpublic_keys;
        all_pub_keys.sort_unstable_by(|left, right| {
            left.split_at(kaspa_bip32::Prefix::LENGTH).1.cmp(right.split_at(kaspa_bip32::Prefix::LENGTH).1)
        });

        let mut pubkeys_from_mnemonics = Vec::with_capacity(mnemonics_and_secrets.len());
        for (mnemonic, _) in mnemonics_and_secrets.iter() {
            let priv_key = storage::PrvKeyData::try_new_from_mnemonic(mnemonic.clone(), None, self.store().encryption_kind()?)?;
            let xpub_key = priv_key.create_xpub(None, MULTISIG_ACCOUNT_KIND.into(), 0).await.unwrap().to_string(Some(prefix));
            pubkeys_from_mnemonics.push(xpub_key);
        }
        pubkeys_from_mnemonics.sort_unstable_by(|left, right| {
            left.split_at(kaspa_bip32::Prefix::LENGTH).1.cmp(right.split_at(kaspa_bip32::Prefix::LENGTH).1)
        });
        all_pub_keys.retain(|v| {
            let found = pubkeys_from_mnemonics.binary_search_by_key(v, |xpub| xpub.as_str());
            found.is_err()
        });
        let additional_pub_keys = all_pub_keys.into_iter().map(String::from).collect();
        let acc = self
            .import_multisig_with_mnemonic(wallet_secret, mnemonics_and_secrets, file.required_signatures, additional_pub_keys)
            .await?;
        Ok(acc)
    }

    pub async fn import_legacy_keydata(
        self: &Arc<Wallet>,
        import_secret: &Secret,
        wallet_secret: &Secret,
        payment_secret: Option<&Secret>,
        notifier: Option<ScanNotifier>,
    ) -> Result<Arc<dyn Account>> {
        use crate::compat::gen0::load_v0_keydata;

        let notifier = notifier.as_ref();
        let keydata = load_v0_keydata(import_secret).await?;

        let mnemonic = Mnemonic::new(keydata.mnemonic.trim(), Language::English)?;
        let prv_key_data = PrvKeyData::try_new_from_mnemonic(mnemonic, payment_secret, self.store().encryption_kind()?)?;
        let prv_key_data_store = self.inner.store.as_prv_key_data_store()?;
        if prv_key_data_store.load_key_data(wallet_secret, &prv_key_data.id).await?.is_some() {
            return Err(Error::PrivateKeyAlreadyExists(prv_key_data.id));
        }

        let account: Arc<dyn Account> = Arc::new(legacy::Legacy::try_new(self, None, prv_key_data.id).await?);

        // activate account (add it to wallet active account list)
        self.active_accounts().insert(account.clone().as_dyn_arc());
        self.legacy_accounts().insert(account.clone().as_dyn_arc());

        // store private key and account
        self.inner.store.batch().await?;
        prv_key_data_store.store(wallet_secret, prv_key_data).await?;
        self.inner.store.clone().as_account_store()?.store_single(&account.to_storage()?, None).await?;
        self.inner.store.flush(wallet_secret).await?;

        let legacy_account = account.clone().as_legacy_account()?;
        legacy_account.create_private_context(wallet_secret, payment_secret, None).await?;

        if self.is_connected() {
            if let Some(notifier) = notifier {
                notifier(0, 0, 0, None);
            }
            account.clone().scan(Some(100), Some(5000)).await?;
        }

        legacy_account.clear_private_context().await?;

        Ok(account)
    }

    pub async fn import_gen1_keydata(self: &Arc<Wallet>, _secret: Secret) -> Result<()> {
        // use crate::derivation::gen1::import::load_v1_keydata;

        // let _keydata = load_v1_keydata(&secret).await?;
        todo!();
        // Ok(())
    }

    pub async fn import_with_mnemonic(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        payment_secret: Option<&Secret>,
        mnemonic: Mnemonic,
        account_kind: AccountKind,
    ) -> Result<Arc<dyn Account>> {
        let prv_key_data = storage::PrvKeyData::try_new_from_mnemonic(mnemonic, payment_secret, self.store().encryption_kind()?)?;
        let prv_key_data_store = self.store().as_prv_key_data_store()?;
        if prv_key_data_store.load_key_data(wallet_secret, &prv_key_data.id).await?.is_some() {
            return Err(Error::PrivateKeyAlreadyExists(prv_key_data.id));
        }
        // let mut is_legacy = false;
        let account: Arc<dyn Account> = match account_kind.as_ref() {
            BIP32_ACCOUNT_KIND => {
                let account_index = 0;
                let xpub_key = prv_key_data.create_xpub(payment_secret, account_kind, account_index).await?;
                let xpub_keys = Arc::new(vec![xpub_key]);
                let ecdsa = false;
                // ---
                Arc::new(bip32::Bip32::try_new(self, None, prv_key_data.id, account_index, xpub_keys, ecdsa).await?)
            }
            LEGACY_ACCOUNT_KIND => Arc::new(legacy::Legacy::try_new(self, None, prv_key_data.id).await?),
            _ => {
                return Err(Error::AccountKindFeature);
            }
        };

        let account_store = self.inner.store.as_account_store()?;
        self.inner.store.batch().await?;
        account_store.store_single(&account.to_storage()?, None).await?;
        self.inner.store.flush(wallet_secret).await?;

        if let Ok(legacy_account) = account.clone().as_legacy_account() {
            self.legacy_accounts().insert(account.clone());
            legacy_account.create_private_context(wallet_secret, None, None).await?;
            legacy_account.clone().start().await?;
            legacy_account.clear_private_context().await?;
        } else {
            account.clone().start().await?;
        }

        // if is_legacy {
        //     account.clone().initialize_private_data(wallet_secret, None, None).await?;
        //     self.legacy_accounts().insert(account.clone());
        // }
        // account.clone().start().await?;
        // if is_legacy {
        //     let derivation = account.clone().as_derivation_capable()?.derivation();
        //     let m = derivation.receive_address_manager();
        //     m.get_range(0..(m.index() + CACHE_ADDRESS_OFFSET))?;
        //     let m = derivation.change_address_manager();
        //     m.get_range(0..(m.index() + CACHE_ADDRESS_OFFSET))?;
        //     account.clone().clear_private_data().await?;
        // }

        Ok(account)
    }

    /// Perform a "2d" scan of account derivations while scanning addresses
    /// in each account (UTXOs up to `address_scan_extent` address derivation).
    /// Report back the last account index that has UTXOs. The scan is performed
    /// until we have encountered at least `account_scan_extent` of empty
    /// accounts.
    pub async fn scan_bip44_accounts(
        self: &Arc<Self>,
        bip39_mnemonic: Secret,
        bip39_passphrase: Option<Secret>,
        address_scan_extent: u32,
        account_scan_extent: u32,
    ) -> Result<u32> {
        let bip39_mnemonic = std::str::from_utf8(bip39_mnemonic.as_ref()).map_err(|_| Error::InvalidMnemonicPhrase)?;
        let mnemonic = Mnemonic::new(bip39_mnemonic, Language::English)?;

        // TODO @aspect - this is not efficient, we need to scan without encrypting prv_key_data
        let prv_key_data =
            storage::PrvKeyData::try_new_from_mnemonic(mnemonic, bip39_passphrase.as_ref(), EncryptionKind::XChaCha20Poly1305)?;

        let mut last_account_index = 0;
        let mut account_index = 0;

        while account_index < last_account_index + account_scan_extent {
            let xpub_key =
                prv_key_data.create_xpub(bip39_passphrase.as_ref(), BIP32_ACCOUNT_KIND.into(), account_index as u64).await?;
            let xpub_keys = Arc::new(vec![xpub_key]);
            let ecdsa = false;
            // ---

            let addresses = bip32::Bip32::try_new(self, None, prv_key_data.id, account_index as u64, xpub_keys, ecdsa)
                .await?
                .get_address_range_for_scan(0..address_scan_extent)?;
            if self.rpc_api().get_utxos_by_addresses(addresses).await?.is_not_empty() {
                last_account_index = account_index;
            }
            account_index += 1;
        }

        Ok(last_account_index)
    }

    pub async fn import_multisig_with_mnemonic(
        self: &Arc<Wallet>,
        wallet_secret: &Secret,
        mnemonics_secrets: Vec<(Mnemonic, Option<Secret>)>,
        minimum_signatures: u16,
        additional_xpub_keys: Vec<String>,
    ) -> Result<Arc<dyn Account>> {
        let mut generated_xpubs = Vec::with_capacity(mnemonics_secrets.len());
        let mut prv_key_data_ids = Vec::with_capacity(mnemonics_secrets.len());
        let prv_key_data_store = self.store().as_prv_key_data_store()?;

        for (mnemonic, payment_secret) in mnemonics_secrets {
            let prv_key_data =
                storage::PrvKeyData::try_new_from_mnemonic(mnemonic, payment_secret.as_ref(), self.store().encryption_kind()?)?;
            if prv_key_data_store.load_key_data(wallet_secret, &prv_key_data.id).await?.is_some() {
                return Err(Error::PrivateKeyAlreadyExists(prv_key_data.id));
            }
            let xpub_key = prv_key_data.create_xpub(payment_secret.as_ref(), MULTISIG_ACCOUNT_KIND.into(), 0).await?; // todo it can be done concurrently
            generated_xpubs.push(xpub_key.to_string(Some(KeyPrefix::XPUB)));
            prv_key_data_ids.push(prv_key_data.id);
            prv_key_data_store.store(wallet_secret, prv_key_data).await?;
        }

        generated_xpubs.sort_unstable();
        let wallet_network = self.network_id()?.network_type();
        let xpub_keys = normalize_and_merge_xpubs(additional_xpub_keys, &generated_xpubs, minimum_signatures, wallet_network)?;

        let min_cosigner_index =
            generated_xpubs.first().and_then(|first_generated| xpub_keys.binary_search(first_generated).ok()).map(|v| v as u8);

        let xpub_keys = xpub_keys
            .into_iter()
            .map(|xpub_key| {
                ExtendedPublicKeySecp256k1::from_str(&xpub_key).map_err(|err| Error::InvalidExtendedPublicKey(xpub_key, err))
            })
            .collect::<Result<Vec<_>>>()?;

        let account: Arc<dyn Account> = Arc::new(
            multisig::MultiSig::try_new(
                self,
                None,
                Arc::new(xpub_keys),
                Some(Arc::new(prv_key_data_ids)),
                min_cosigner_index,
                minimum_signatures,
                false,
            )
            .await?,
        );

        self.inner.store.clone().as_account_store()?.store_single(&account.to_storage()?, None).await?;
        // Mirror `create_account_multisig`'s post-write commit; clears LocalStore's
        // modified flag so the next wallet open does not trip the dirty-store guard.
        self.inner.store.commit(wallet_secret).await?;
        account.clone().start().await?;

        Ok(account)
    }

    async fn rename(&self, title: Option<String>, filename: Option<String>, wallet_secret: &Secret) -> Result<()> {
        let store = self.store();
        store.rename(wallet_secret, title.as_deref(), filename.as_deref()).await?;
        Ok(())
    }

    async fn ensure_default_account_impl(
        self: Arc<Self>,
        wallet_secret: &Secret,
        payment_secret: Option<&Secret>,
        kind: AccountKind,
        mnemonic_phrase: Option<&Secret>,
        guard: &WalletGuard<'_>,
    ) -> Result<AccountDescriptor> {
        if kind != BIP32_ACCOUNT_KIND {
            return Err(Error::custom("Account kind is not supported"));
        }

        let account = self.store().as_account_store()?.iter(None).await?.next().await;

        if let Some(Ok((stored_account, stored_metadata))) = account {
            let account_descriptor = try_load_account(&self, stored_account, stored_metadata).await?.descriptor()?;
            Ok(account_descriptor)
        } else {
            let mnemonic_phrase_string = if let Some(phrase) = mnemonic_phrase.cloned() {
                phrase
            } else {
                let mnemonic = Mnemonic::random(WordCount::Words24, Language::English)?;
                Secret::from(mnemonic.phrase_string())
            };

            let prv_key_data_args =
                PrvKeyDataCreateArgs::new(None, payment_secret.cloned(), mnemonic_phrase_string, PrvKeyDataVariantKind::Mnemonic);

            self.store().batch().await?;
            let prv_key_data_id = self.clone().create_prv_key_data(wallet_secret, prv_key_data_args).await?;

            let account_create_args = AccountCreateArgs::new_bip32(prv_key_data_id, payment_secret.cloned(), None, None);

            let account = self.clone().create_account(wallet_secret, account_create_args, false, guard).await?;

            self.store().flush(wallet_secret).await?;

            Ok(account.descriptor()?)
        }
    }

    pub fn network_format_xpub(&self, xpub_key: &ExtendedPublicKeySecp256k1) -> String {
        NetworkTaggedXpub::from((xpub_key.clone(), self.network_id().unwrap())).to_string()
    }
}

/// Normalize every user-supplied xpub to the canonical `xpub` BIP-32 prefix,
/// merge with the wallet-generated xpub set into a single sorted vector, and
/// validate that the resulting K-of-N parameters fit consensus rules.
///
/// Validation order:
/// 1. `min_sigs >= 1`.
/// 2. The final cosigner count `N` does not exceed
///    `kaspa_txscript::MAX_PUB_KEYS_PER_MUTLTISIG` (the consensus
///    `OpCheckMultiSig` stack-pubkey-count cap).
/// 3. `min_sigs <= N` (otherwise the signature threshold is mathematically
///    unreachable).
/// 4. The Schnorr P2SH redeem script predicted from `(min_sigs, N)` fits
///    the consensus script-element-size limit
///    `kaspa_txscript::MAX_SCRIPT_ELEMENT_SIZE`. The script_sig that
///    spends a P2SH multisig pushes the redeem script as a single
///    PUSHDATA element; an element above the limit cannot be pushed.
///
/// `sorted_generated_xpubs` MUST already be sorted in ascending lexicographic
/// order so callers can subsequently resolve a cosigner's position via
/// `binary_search`. Network-version prefixes (`ktub`, `kpub`, `tpub`, `ypub`,
/// `zpub`) carry no key material; the base58-decoded key bytes are
/// prefix-invariant, so re-encoding under `KeyPrefix::XPUB` preserves the
/// parsed public key while making the lexicographic-sort order deterministic
/// across both code paths that build a multisig account.
pub(crate) fn normalize_and_merge_xpubs(
    user_xpubs: Vec<String>,
    sorted_generated_xpubs: &[String],
    min_sigs: u16,
    wallet_network: kaspa_consensus_core::network::NetworkType,
) -> Result<Vec<String>> {
    // Validate every user-supplied xpub's BIP-32 prefix against the
    // wallet's network BEFORE the canonical prefix rewrite. The accept-list
    // for kaspa-network-discriminating prefixes is `KPUB` on Mainnet and
    // `KTUB` on Testnet / Simnet / Devnet (per `wallet/bip32/src/prefix.rs`).
    // Foreign prefixes (`TPUB`, `YPUB`, `ZPUB`) and the canonical-stripped
    // `XPUB` form are rejected at user-input time, since the canonical form
    // is what the wallet PERSISTS internally after normalization and a
    // user-supplied `XPUB` carries no recoverable network discriminator.
    // Wallet-generated xpubs in `sorted_generated_xpubs` were emitted as
    // `XPUB` at construction time on the wallet's own network by definition
    // and bypass this check by virtue of not being in the user-supplied set.
    // Already-persisted wallets whose `xpub_keys` carry `XPUB` entries also
    // bypass: this validation runs at user-input time only, not on
    // storage-read paths.
    use kaspa_consensus_core::network::NetworkType;
    for raw_xpub in user_xpubs.iter() {
        let parsed = ExtendedKey::from_str(raw_xpub)?;
        let accepted = matches!(
            (parsed.prefix, wallet_network),
            (KeyPrefix::KPUB, NetworkType::Mainnet)
                | (KeyPrefix::KTUB, NetworkType::Testnet | NetworkType::Simnet | NetworkType::Devnet)
        );
        if !accepted {
            return Err(Error::MultisigXpubNetworkMismatch { supplied_prefix: parsed.prefix, wallet_network });
        }
    }

    let mut normalized: Vec<String> = user_xpubs
        .into_iter()
        .map(|xpub| {
            ExtendedKey::from_str(&xpub).map(|mut xpub| {
                xpub.prefix = KeyPrefix::XPUB;
                xpub.to_string()
            })
        })
        .collect::<Result<Vec<_>, kaspa_bip32::Error>>()?;
    normalized.extend_from_slice(sorted_generated_xpubs);
    normalized.sort_unstable();

    let n = normalized.len();
    let max = kaspa_txscript::MAX_PUB_KEYS_PER_MUTLTISIG as usize;
    if n > max {
        return Err(Error::MultisigPubKeyCountExceedsConsensus { count: n, max });
    }
    if min_sigs == 0 || (min_sigs as usize) > n {
        return Err(Error::MultisigInvalidThreshold { k: min_sigs, n });
    }
    let predicted = predicted_schnorr_redeem_script_size(min_sigs, n);
    if predicted > kaspa_txscript::MAX_SCRIPT_ELEMENT_SIZE {
        return Err(Error::MultisigRedeemScriptExceedsElementSize { size: predicted, max: kaspa_txscript::MAX_SCRIPT_ELEMENT_SIZE });
    }
    // After sort, duplicate xpubs are adjacent; reject so the redeem script's
    // pubkey list does not collapse two cosigners onto the same slot (a single
    // signer producing two signatures could otherwise satisfy K of the
    // collapsed slots).
    if let Some(window) = normalized.windows(2).find(|w| w[0] == w[1]) {
        return Err(Error::MultisigDuplicateXpub { xpub: window[0].clone() });
    }

    Ok(normalized)
}

/// Predict the byte size of the canonical Schnorr P2SH multisig redeem script
/// for given `(min_sigs, n)` -- matching what `kaspa_txscript::multisig_redeem_script`
/// emits -- so creation can refuse parameter combinations that would not fit a
/// single P2SH PUSHDATA element.
///
/// Layout: `K` (`canonical_i64_size`) + `N` 32-byte Schnorr pubkey pushdatas
/// (`1 + 32` bytes each) + `N` (`canonical_i64_size`) + `OpCheckMultiSig`
/// (1 byte). The K/N integer-push sizes are delegated to
/// [`kaspa_txscript::ScriptBuilder::canonical_i64_size`], which is the
/// int-push counterpart of `canonical_data_size` and is branch-for-branch
/// derived from `ScriptBuilder::add_i64` -- the same encoder
/// `multisig_redeem_script` invokes. The cross-check test
/// [`multisig_tests::predicted_schnorr_redeem_script_size_matches_canonical_builder`]
/// guards the parametric K/N sweep against any future drift on either side.
///
/// Not `const fn`: `canonical_i64_size` calls `OpcodeData::<i64>::serialize`,
/// which allocates a `Vec`. The sole caller in `normalize_and_merge_xpubs`
/// runs in async/non-const context, so the downgrade has no callsite impact.
fn predicted_schnorr_redeem_script_size(min_sigs: u16, n: usize) -> usize {
    const SCHNORR_PUBKEY_PUSH_LEN: usize = 1 + secp256k1::constants::SCHNORR_PUBLIC_KEY_SIZE;
    kaspa_txscript::script_builder::ScriptBuilder::canonical_i64_size(min_sigs as i64)
        + SCHNORR_PUBKEY_PUSH_LEN * n
        + kaspa_txscript::script_builder::ScriptBuilder::canonical_i64_size(n as i64)
        + 1
}

// fn decrypt_mnemonic<T: AsRef<[u8]>>(
//     num_threads: u32,
//     EncryptedMnemonic { cipher, salt }: EncryptedMnemonic<T>,
//     pass: &[u8],
// ) -> Result<String> {
//     let params = argon2::ParamsBuilder::new().t_cost(1).m_cost(64 * 1024).p_cost(num_threads).output_len(32).build().unwrap();
//     let mut key = [0u8; 32];
//     argon2::Argon2::new(argon2::Algorithm::Argon2id, Default::default(), params)
//         .hash_password_into(pass, salt.as_ref(), &mut key[..])
//         .unwrap();
//     let mut aead = chacha20poly1305::XChaCha20Poly1305::new(Key::from_slice(&key));
//     let (nonce, ciphertext) = cipher.as_ref().split_at(24);

//     let decrypted = aead.decrypt(nonce.into(), ciphertext).unwrap();
//     Ok(unsafe { String::from_utf8_unchecked(decrypted) })
// }

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod test {
    // use hex_literal::hex;

    // use super::*;
    // use kaspa_addresses::Address;

    /*
    use workflow_rpc::client::ConnectOptions;
    use std::{str::FromStr, thread::sleep, time};
    use crate::derivation::gen1;
    use crate::utxo::{UtxoContext, UtxoContextBinding, UtxoIterator};
    use kaspa_addresses::{Prefix, Version};
    use kaspa_bip32::{ChildNumber, ExtendedPrivateKey, SecretKey};
    use kaspa_consensus_core::subnets::SUBNETWORK_ID_NATIVE;
    use kaspa_consensus_wasm::{sign_transaction, SignableTransaction, Transaction, TransactionInput, TransactionOutput};
    use kaspa_txscript::pay_to_address_script;

    async fn create_utxos_context_with_addresses(
        rpc: Arc<DynRpcApi>,
        addresses: Vec<Address>,
        current_daa_score: u64,
        core: &UtxoProcessor,
    ) -> Result<UtxoContext> {
        let utxos = rpc.get_utxos_by_addresses(addresses).await?;
        let utxo_context = UtxoContext::new(core, UtxoContextBinding::default());
        let entries = utxos.into_iter().map(|entry| entry.into()).collect::<Vec<_>>();
        for entry in entries.into_iter() {
            utxo_context.insert(entry, current_daa_score, false).await?;
        }
        Ok(utxo_context)
    }

    #[allow(dead_code)]
    // #[tokio::test]
    async fn wallet_test() -> Result<()> {
        println!("Creating wallet...");
        let resident_store = Wallet::resident_store()?;
        let wallet = Arc::new(Wallet::try_new(resident_store, None)?);

        let rpc_api = wallet.rpc_api();
        let utxo_processor = wallet.utxo_processor();

        let wrpc_client = wallet.wrpc_client().expect("Unable to obtain wRPC client");

        let info = rpc_api.get_block_dag_info().await?;
        let current_daa_score = info.virtual_daa_score;

        let _connect_result = wrpc_client.connect(ConnectOptions::fallback()).await;
        //println!("connect_result: {_connect_result:?}");

        let _result = wallet.start().await;
        //println!("wallet.task(): {_result:?}");
        let result = wallet.get_info().await;
        println!("wallet.get_info(): {result:#?}");

        let address = Address::try_from("kaspatest:qz7ulu4c25dh7fzec9zjyrmlhnkzrg4wmf89q7gzr3gfrsj3uz6xjceef60sd")?;

        let utxo_context =
            self::create_utxos_context_with_addresses(rpc_api.clone(), vec![address.clone()], current_daa_score, utxo_processor)
                .await?;

        let utxo_set_balance = utxo_context.calculate_balance().await;
        println!("get_utxos_by_addresses: {utxo_set_balance:?}");

        let to_address = Address::try_from("kaspatest:qpakxqlesqywgkq7rg4wyhjd93kmw7trkl3gpa3vd5flyt59a43yyn8vu0w8c")?;
        let mut iter = UtxoIterator::new(&utxo_context);
        let utxo = iter.next().unwrap();
        let utxo = (*utxo.utxo).clone();
        let selected_entries = vec![utxo];

        let entries = &selected_entries;

        let inputs = selected_entries
            .iter()
            .enumerate()
            .map(|(sequence, utxo)| TransactionInput::new(utxo.outpoint.clone(), vec![], sequence as u64, 0))
            .collect::<Vec<TransactionInput>>();

        let tx = Transaction::new(
            0,
            inputs,
            vec![TransactionOutput::new(1000, &pay_to_address_script(&to_address))],
            0,
            SUBNETWORK_ID_NATIVE,
            0,
            vec![],
        )?;

        let mtx = SignableTransaction::new(tx, (*entries).clone().into());

        let derivation_path =
            gen1::WalletDerivationManager::build_derivate_path(false, 0, None, Some(kaspa_bip32::AddressType::Receive))?;

        let xprv = "kprv5y2qurMHCsXYrNfU3GCihuwG3vMqFji7PZXajMEqyBkNh9UZUJgoHYBLTKu1eM4MvUtomcXPQ3Sw9HZ5ebbM4byoUciHo1zrPJBQfqpLorQ";

        let xkey = ExtendedPrivateKey::<SecretKey>::from_str(xprv)?.derive_path(derivation_path)?;

        let xkey = xkey.derive_child(ChildNumber::new(0, false)?)?;

        // address test
        let address_test = Address::new(Prefix::Testnet, Version::PubKey, &xkey.public_key().to_bytes()[1..]);
        let address_str: String = address_test.clone().into();
        assert_eq!(address, address_test, "Addresses don't match");
        println!("address: {address_str}");

        let private_keys = vec![xkey.to_bytes()];

        println!("mtx: {mtx:?}");

        let mtx = sign_transaction(mtx, private_keys, true)?;

        let utxo_context =
            self::create_utxos_context_with_addresses(rpc_api.clone(), vec![to_address.clone()], current_daa_score, utxo_processor)
                .await?;
        let to_balance = utxo_context.calculate_balance().await;
        println!("to address balance before tx submit: {to_balance:?}");

        let result = rpc_api.submit_transaction(mtx.into(), false).await?;

        println!("tx submit result, {:?}", result);
        println!("sleep for 5s...");
        sleep(time::Duration::from_millis(5000));
        let utxo_context =
            self::create_utxos_context_with_addresses(rpc_api.clone(), vec![to_address.clone()], current_daa_score, utxo_processor)
                .await?;
        let to_balance = utxo_context.calculate_balance().await;
        println!("to address balance after tx submit: {to_balance:?}");

        Ok(())
    }
    */
}

#[cfg(not(target_arch = "wasm32"))]
#[cfg(test)]
mod multisig_tests {
    use super::*;
    use crate::account::pskb::finalize_pskt_one_or_more_sig_and_redeem_script;
    use crate::account::pskb::pskb_signer_for_multisig_cosigner;
    use crate::account::variants::multisig::{MULTISIG_ACCOUNT_KIND, MultiSig};
    use kaspa_bip32::{ChildNumber, Language, Mnemonic, Prefix as KeyPrefix};
    use kaspa_consensus_core::config::params::Params;
    use kaspa_consensus_core::network::{NetworkId, NetworkType};
    use kaspa_txscript::{multisig_redeem_script, pay_to_address_script, pay_to_script_hash_script};
    use kaspa_wallet_pskt::bundle::Bundle;
    use kaspa_wallet_pskt::input::InputBuilder;
    use kaspa_wallet_pskt::pskt::{Creator, PSKT};

    /// Build an empty Testnet-10 resident-store wallet ready for account
    /// import / creation; used as the substrate for every multisig test in
    /// this module.
    async fn test_wallet() -> Arc<Wallet> {
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
        wallet
    }

    /// Derive the canonical XPUB-prefixed extended public key from a BIP-39
    /// mnemonic phrase at the multisig account-kind derivation path.
    async fn xpub_from_mnemonic_phrase(phrase: &str) -> String {
        let mnemonic = Mnemonic::new(phrase, Language::English).unwrap();
        let prv_key_data = PrvKeyData::try_new_from_mnemonic(mnemonic, None, EncryptionKind::XChaCha20Poly1305).unwrap();
        let xpub = prv_key_data.create_xpub(None, MULTISIG_ACCOUNT_KIND.into(), 0).await.unwrap();
        xpub.to_string(Some(KeyPrefix::XPUB))
    }

    /// Derive a user-supplied external xpub for the test wallet's network
    /// (Testnet); the helper re-encodes the canonical XPUB form to KTUB so
    /// it passes the cross-network prefix gate when threaded into
    /// `Wallet::create_account_multisig` / `import_multisig_with_mnemonic`.
    async fn external_xpub_for_testnet(phrase: &str) -> String {
        let raw = xpub_from_mnemonic_phrase(phrase).await;
        let mut k = kaspa_bip32::ExtendedKey::from_str(&raw).unwrap();
        k.prefix = KeyPrefix::KTUB;
        k.to_string()
    }

    /// Generate `count` fresh random 24-word English BIP-39 mnemonics for
    /// in-test local-cosigner construction.
    async fn make_local_mnemonics(count: usize) -> Vec<Mnemonic> {
        let mut out = Vec::with_capacity(count);
        for _ in 0..count {
            out.push(Mnemonic::random(kaspa_bip32::WordCount::Words24, Language::English).unwrap());
        }
        out
    }

    /// Network-version prefixes carry no key material; for the wallet's own
    /// network the supplied prefix re-encodes to the canonical `xpub` form
    /// preserving the parsed public key. The cross-network gate narrows the user-input
    /// accept-list to the network-discriminating kaspa prefixes (`KPUB` on
    /// Mainnet, `KTUB` on Testnet/Simnet/Devnet); rejection of the other
    /// four entries of the full BIP-32 PUBLIC prefix set is exercised by
    /// the cross-network reject tests below.
    #[tokio::test]
    async fn multisig_xpub_prefix_invariant() {
        let canonical_xpub =
            xpub_from_mnemonic_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
                .await;
        let generated_xpub =
            xpub_from_mnemonic_phrase("legal winner thank year wave sausage worth useful legal winner thank yellow").await;

        let mut generated_xpubs = vec![generated_xpub.clone()];
        generated_xpubs.sort_unstable();

        // For each network, the accepted prefix re-encodes through the canonical
        // form and yields a normalized vector whose `xpub`-encoded entries equal
        // those produced from the canonical form via the wallet-generated bypass.
        for (network, accepted_prefix) in [(NetworkType::Mainnet, KeyPrefix::KPUB), (NetworkType::Testnet, KeyPrefix::KTUB)] {
            let mut reprefixed = kaspa_bip32::ExtendedKey::from_str(&canonical_xpub).unwrap();
            reprefixed.prefix = accepted_prefix;
            let user_xpub = reprefixed.to_string();

            // Drive the canonical-form entry through `sorted_generated_xpubs` so it
            // bypasses cross-network validation (wallet-generated xpubs are XPUB-form by
            // construction and skip the user-input check).
            let mut gens_with_canonical = generated_xpubs.clone();
            gens_with_canonical.push(canonical_xpub.clone());
            gens_with_canonical.sort_unstable();
            let canonical_output = normalize_and_merge_xpubs(Vec::new(), &gens_with_canonical, 2, network).unwrap();

            let output = normalize_and_merge_xpubs(vec![user_xpub], &generated_xpubs, 2, network).unwrap();
            assert_eq!(output, canonical_output, "prefix {accepted_prefix:?} on {network:?} produced a different normalized set");
        }
    }

    /// A multisig account's address-watch surface enumerates every
    /// cosigner-prefix family in `[0, N)`. Each cosigner-prefix family carries
    /// a distinct `(receive_address_manager, change_address_manager)` pair
    /// driven by a different BIP-32 child step at the cosigner-index slot, so
    /// the per-family first-receive addresses are pairwise distinct. The
    /// local family aliases the wallet's `receive_address_manager` exactly,
    /// so every caller that already held an `Arc` to it continues to
    /// operate against the same backing `AddressManager`.
    #[tokio::test]
    async fn multisig_sync_layer_enumerates_all_cosigner_prefix_families() {
        for &(n, k) in &[(3usize, 2u16), (4, 2), (5, 3), (6, 3)] {
            let wallet = test_wallet().await;
            let wallet_secret = Secret::new(vec![]);

            // One local seed; the remaining `n - 1` xpubs join as external.
            let local_mnemonic = make_local_mnemonics(1).await.into_iter().next().unwrap();
            let prv_key_data =
                storage::PrvKeyData::try_new_from_mnemonic(local_mnemonic.clone(), None, EncryptionKind::XChaCha20Poly1305).unwrap();
            let prv_key_data_store = wallet.store().as_prv_key_data_store().unwrap();
            prv_key_data_store.store(&wallet_secret, prv_key_data.clone()).await.unwrap();
            wallet.inner.store.commit(&wallet_secret).await.unwrap();

            // `n - 1` external KTUB-prefixed xpubs derived from random
            // mnemonics; matches the cosigner-onboarding shape where peers
            // exchange xpubs only.
            let mut external_xpubs = Vec::with_capacity(n - 1);
            let external_mnemonics = make_local_mnemonics(n - 1).await;
            for m in external_mnemonics.iter() {
                let raw_xpub = {
                    let kd = storage::PrvKeyData::try_new_from_mnemonic(m.clone(), None, EncryptionKind::XChaCha20Poly1305).unwrap();
                    let xpub = kd.create_xpub(None, MULTISIG_ACCOUNT_KIND.into(), 0).await.unwrap();
                    xpub.to_string(Some(KeyPrefix::XPUB))
                };
                let mut k_xpub = kaspa_bip32::ExtendedKey::from_str(&raw_xpub).unwrap();
                k_xpub.prefix = KeyPrefix::KTUB;
                external_xpubs.push(k_xpub.to_string());
            }

            let create_args = vec![PrvKeyDataArgs::new(prv_key_data.id, None)];
            let account = wallet.create_account_multisig(&wallet_secret, create_args, external_xpubs.clone(), None, k).await.unwrap();

            // Cast to a `DerivationCapableAccount` so we can reach the
            // `AddressDerivationManager` and its newly exposed families.
            let derivation_capable = account.clone().as_derivation_capable().unwrap();
            let derivation = derivation_capable.derivation();
            let families = derivation.address_manager_families();

            assert_eq!(families.len(), n, "({n},{k}) cell: expected N={n} cosigner-prefix families, got {}", families.len());

            for (i, family) in families.iter().enumerate() {
                assert_eq!(family.cosigner_index, i as u32, "({n},{k}) family {i}: cosigner_index slot must equal vector position");
            }

            // Every family produces a distinct first-receive address: the
            // BIP-32 child step at the cosigner_index slot differs per family,
            // so the per-xpub derived child pubkeys differ, the redeem-script
            // bytes differ, and the BLAKE2B P2SH hash differs.
            let mut receive_addresses = Vec::with_capacity(n);
            for family in families.iter() {
                receive_addresses.push(family.receive.current_address().unwrap());
            }
            for i in 0..n {
                for j in (i + 1)..n {
                    assert_ne!(
                        receive_addresses[i], receive_addresses[j],
                        "({n},{k}): family {i} and family {j} must derive distinct P2SH receive addresses"
                    );
                }
            }

            // Local-family aliasing invariant: the family at the local
            // `cosigner_index` aliases the trait-exposed
            // `receive_address_manager` / `change_address_manager` Arcs, so
            // every caller against `derivation.receive_address_manager()`
            // continues to operate against the same backing AddressManager.
            let multisig = account.downcast_arc::<MultiSig>().unwrap();
            let local_cosigner_index = multisig.cosigner_index() as usize;
            let local_family = &families[local_cosigner_index];
            let local_receive = derivation.receive_address_manager();
            let local_change = derivation.change_address_manager();
            assert!(
                Arc::ptr_eq(&local_family.receive, &local_receive),
                "({n},{k}): local-family receive AddressManager must alias the trait-exposed receive_address_manager"
            );
            assert!(
                Arc::ptr_eq(&local_family.change, &local_change),
                "({n},{k}): local-family change AddressManager must alias the trait-exposed change_address_manager"
            );
        }
    }

    /// `create_account_multisig` and `import_multisig_with_mnemonic` produce
    /// byte-equal P2SH first-receive addresses when given equivalent inputs
    /// (same mnemonics + same external xpub + same `minimum_signatures`).
    /// Without the shared `normalize_and_merge_xpubs` helper the create-path
    /// would skip prefix normalization on the user-supplied xpub and mix
    /// `ktub`/`kpub` into the sort, producing a different sorted xpub set
    /// than the import-path.
    #[tokio::test]
    async fn multisig_create_import_parity() {
        let mnemonics = make_local_mnemonics(2).await;
        let mnemonic_a = mnemonics[0].clone();
        let mnemonic_b = mnemonics[1].clone();
        let external_xpub =
            xpub_from_mnemonic_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
                .await;
        let external_xpub_ktub = {
            let mut k = kaspa_bip32::ExtendedKey::from_str(&external_xpub).unwrap();
            k.prefix = KeyPrefix::KTUB;
            k.to_string()
        };

        // Create path.
        let create_wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let prv_key_data_a =
            storage::PrvKeyData::try_new_from_mnemonic(mnemonic_a.clone(), None, EncryptionKind::XChaCha20Poly1305).unwrap();
        let prv_key_data_b =
            storage::PrvKeyData::try_new_from_mnemonic(mnemonic_b.clone(), None, EncryptionKind::XChaCha20Poly1305).unwrap();
        let store_a = create_wallet.store().as_prv_key_data_store().unwrap();
        store_a.store(&wallet_secret, prv_key_data_a.clone()).await.unwrap();
        store_a.store(&wallet_secret, prv_key_data_b.clone()).await.unwrap();
        create_wallet.inner.store.commit(&wallet_secret).await.unwrap();
        let create_args = vec![PrvKeyDataArgs::new(prv_key_data_a.id, None), PrvKeyDataArgs::new(prv_key_data_b.id, None)];
        let create_account = create_wallet
            .create_account_multisig(&wallet_secret, create_args, vec![external_xpub_ktub.clone()], None, 2)
            .await
            .unwrap();
        let create_address = create_account.receive_address().unwrap();

        // Import path with the SAME mnemonics + SAME external xpub (also `ktub`-prefixed).
        let import_wallet = test_wallet().await;
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = vec![(mnemonic_a.clone(), None), (mnemonic_b.clone(), None)];
        let import_account = import_wallet
            .import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![external_xpub_ktub.clone()])
            .await
            .unwrap();
        let import_address = import_account.receive_address().unwrap();

        assert_eq!(create_address, import_address, "create-path and import-path produce identical P2SH first-receive addresses");
    }

    /// After `import_multisig_with_mnemonic` returns, a subsequent `Wallet::open`
    /// proceeds without panic. `LocalStore::open` panics when
    /// `is_modified == true`. The resident-store test substrate that
    /// `Wallet::resident_store()` returns uses `Store::Resident` mode in which
    /// `set_modified` is a no-op and `is_modified` always returns `false`
    /// (see `LocalStore::set_modified` / `LocalStore::is_modified` bodies).
    /// The resident substrate therefore
    /// cannot exercise the panic site by construction; this test pins only
    /// that the import path does not introduce a different panic of its own
    /// and that `Wallet::open` reaches `try_load`. The runtime evidence
    /// against the disk-backed `Store::Storage` substrate is the Validator's
    /// gate on testnet.
    #[tokio::test]
    async fn multisig_post_import_open() {
        let mnemonics = make_local_mnemonics(2).await;
        let external_xpub =
            external_xpub_for_testnet("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
                .await;

        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);

        // Import the multisig account. Without a `commit` after the account
        // `store_single`, the local store's `is_modified` flag would remain set.
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![external_xpub.clone()]).await.unwrap();

        // Re-open the same wallet payload. `LocalStore::open` checks the modified
        // flag first and panics on `is_modified == true`. With the import-path
        // `commit`, the flag is cleared by the time `open` runs and the open
        // routes through to `try_load`. In the resident-store
        // test substrate `try_load` fails because no file was persisted to the
        // "disk" surface; that Err return is the all-clear signal: the modified
        // flag check was reached without panicking and a non-panic return path
        // was taken.
        let lock = wallet.guard();
        let guard = lock.lock().await;
        let open_result = wallet.open(&wallet_secret, None, WalletOpenArgs::default(), &guard).await;
        assert!(
            matches!(open_result, Err(Error::NoWalletInStorage(_))),
            "post-import Wallet::open must reach try_load (resident store reports NoWalletInStorage) without panicking; \
             got {open_result:?}",
        );
    }

    /// For a fixed `(N=2, K=2)` multisig account, the per-cosigner signing
    /// primitive inserts a `partial_sigs[pub_key]` entry where `pub_key` equals
    /// the pubkey reached by deriving the cosigner's own xpub through the
    /// unhardened tail the AddressDerivationManager walks for receive[0]. The
    /// BIP-32 derivation step is the account's persisted derivation index -- a
    /// single value applied to every cosigner's xpub -- NOT the cosigner's
    /// position in the xpub vector. Pins the redeem-script-slot match invariant
    /// the `OpCheckMultiSig` verifier relies on at consensus time.
    #[tokio::test]
    async fn test_pskb_signer_for_multisig_cosigner_known_fixture() {
        // Deterministic BIP-39 24-word phrases so the test is a true "known
        // fixture": same mnemonics in, same xpubs derived, same signing pubkey
        // expected at each cosigner position across runs.
        let phrase_a = "caution guide valley easily latin already visual fancy fork car switch runway \
                        vicious polar surprise fence boil light nut invite fiction visa hamster coyote";
        let phrase_b = "fiber boy desk trip pitch snake table awkward endorse car learn forest \
                        solid ticket enemy pink gesture wealth iron chaos clock gather honey farm";
        let mnemonics = [Mnemonic::new(phrase_a, Language::English).unwrap(), Mnemonic::new(phrase_b, Language::English).unwrap()];
        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let account = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![]).await.unwrap();

        // Build a single-input unsigned PSKT pointing at the multisig's receive address.
        let receive_address = account.receive_address().unwrap();
        let script_public_key = pay_to_address_script(&receive_address);
        let utxo =
            kaspa_consensus_core::tx::UtxoEntry { amount: 100_000_000, script_public_key, block_daa_score: 1, is_coinbase: false };
        let input = InputBuilder::default()
            .utxo_entry(utxo)
            .previous_outpoint(kaspa_consensus_core::tx::TransactionOutpoint {
                transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[0xab; 32]),
                index: 0,
            })
            .sig_op_count(2)
            .build()
            .unwrap();
        let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
        let pskt_inner = pskt_creator.constructor().input(input);
        let bundle = Bundle::from(pskt_inner);

        let multisig: Arc<MultiSig> = account.clone().downcast_arc().expect("account is multisig");
        let prv_key_data_ids = multisig.prv_key_data_ids().as_ref().expect("local cosigner ids").clone();
        let network_id = wallet.network_id().unwrap();
        let xpub_keys = account.xpub_keys().expect("multisig xpubs").clone();
        // The shared BIP-32 derivation step the multisig persisted at create-time and
        // reuses on every cosigner's xpub during address derivation.
        let multisig_derivation_index = account.clone().as_derivation_capable().unwrap().cosigner_index();

        // Sign with each local cosigner and verify the inserted pubkey matches the
        // redeem-script slot the verifier walks to at the cosigner's position.
        let prv_key_data_store = wallet.store().as_prv_key_data_store().unwrap();
        for prv_key_data_id in prv_key_data_ids.iter() {
            let prv_key_data =
                prv_key_data_store.load_key_data(&wallet_secret, prv_key_data_id).await.unwrap().expect("prv_key_data loaded");

            // Resolve THIS cosigner's position in the persisted xpub vector -- that is the
            // redeem-script slot whose pubkey this cosigner's derived signing key must
            // match. Iterating the vector tolerates non-sorted orderings (a wallet
            // persisted under a code path that did not normalize xpub prefixes stores the
            // vector in mixed-prefix sort order whose entries reorder under re-encoding).
            let this_xpub = prv_key_data.create_xpub(None, MULTISIG_ACCOUNT_KIND.into(), 0).await.unwrap();
            let this_xpub_string = this_xpub.to_string(Some(KeyPrefix::XPUB));
            let cosigner_position = xpub_keys
                .iter()
                .position(|k| k.to_string(Some(KeyPrefix::XPUB)) == this_xpub_string)
                .expect("cosigner xpub present in account xpub set");

            let signed_bundle = pskb_signer_for_multisig_cosigner(
                &bundle,
                account.clone(),
                &prv_key_data,
                None,
                multisig_derivation_index,
                network_id,
            )
            .await
            .unwrap();

            // The signed bundle's single input has exactly one partial_sigs entry: this cosigner's.
            let signed_inputs = &signed_bundle.as_ref()[0].inputs;
            assert_eq!(signed_inputs.len(), 1, "signed bundle preserves input count");
            assert_eq!(signed_inputs[0].partial_sigs.len(), 1, "primitive inserts exactly one signature per input");
            let inserted_pub_key = signed_inputs[0].partial_sigs.keys().next().copied().unwrap();

            // BIP-32 derivation determinism: walking the cosigner's own xpub at
            // `xpub_keys[cosigner_position]` through the same unhardened tail
            // `multisig_derivation_index / receive / 0` that the AddressDerivationManager
            // uses produces the pubkey at the cosigner's redeem-script slot. The signing
            // key the primitive derives from this cosigner's xprv MUST match.
            let base_xpub = xpub_keys[cosigner_position].clone();
            let cosigner_branch = base_xpub.derive_child(ChildNumber::new(multisig_derivation_index, false).unwrap()).unwrap();
            let receive_branch = cosigner_branch.derive_child(ChildNumber::new(0, false).unwrap()).unwrap();
            let expected_pub_key = *receive_branch.derive_child(ChildNumber::new(0, false).unwrap()).unwrap().public_key();

            assert_eq!(
                inserted_pub_key, expected_pub_key,
                "per-cosigner derived pubkey at position {cosigner_position} matches the redeem-script slot",
            );
        }
    }

    /// `MultiSig::pskb_sign` populates `input.redeem_script` on every PSKT
    /// input before per-cosigner signing.
    ///
    /// The trait-default `Account::pskb_sign` routes through the generic
    /// `pskb_signer_for_address` helper which has no concept of multisig and
    /// leaves `input.redeem_script` empty; the Finalizer's `None` branch
    /// then emits a `script_sig` whose P2SH-hash mismatch is rejected at
    /// consensus extract. The override fixes this by populating
    /// `input.redeem_script` via the shared helper and routing through
    /// `pskb_signer_for_multisig_cosigner` for the per-cosigner signature
    /// chain. Test gates AC-D2-1 of the rev-7 spec.
    ///
    /// Idempotency cell: a second `pskb_sign` invocation on an already
    /// populated bundle leaves `redeem_script` unchanged (the helper's
    /// `.is_some()` skip-guard), so the multi-party PSKT exchange chain does
    /// not let a downstream cosigner overwrite an upstream cosigner's
    /// redeem-script contribution.
    #[tokio::test]
    async fn multisig_pskb_sign_populates_redeem_script() {
        // The same `(2, 2)` known-fixture mnemonics
        // `test_pskb_signer_for_multisig_cosigner_known_fixture` uses, so the
        // expected slot pubkeys and redeem-script bytes are reproducible from
        // the same canonical derivation walk. `\`-continuation collapses the
        // following line's leading whitespace per Rust string-literal rules.
        let phrase_a = "caution guide valley easily latin already visual fancy fork car switch runway \
                        vicious polar surprise fence boil light nut invite fiction visa hamster coyote";
        let phrase_b = "fiber boy desk trip pitch snake table awkward endorse car learn forest \
                        solid ticket enemy pink gesture wealth iron chaos clock gather honey farm";
        let mnemonics = [Mnemonic::new(phrase_a, Language::English).unwrap(), Mnemonic::new(phrase_b, Language::English).unwrap()];
        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let account = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![]).await.unwrap();

        // Build a single-input unsigned PSKT pointing at the multisig's receive address.
        let receive_address = account.receive_address().unwrap();
        let script_public_key = pay_to_address_script(&receive_address);
        let utxo =
            kaspa_consensus_core::tx::UtxoEntry { amount: 100_000_000, script_public_key, block_daa_score: 1, is_coinbase: false };
        let input = InputBuilder::default()
            .utxo_entry(utxo)
            .previous_outpoint(kaspa_consensus_core::tx::TransactionOutpoint {
                transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[0xab; 32]),
                index: 0,
            })
            .sig_op_count(2)
            .build()
            .unwrap();
        let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
        let pskt_inner = pskt_creator.constructor().input(input);
        let bundle = Bundle::from(pskt_inner);

        // The fresh bundle has no redeem-script on its input -- the
        // PSKT-conversion path builds inputs with `redeem_script: None`.
        assert!(
            bundle.as_ref()[0].inputs[0].redeem_script.is_none(),
            "pre-condition: PSKT-conversion path leaves redeem_script unpopulated",
        );

        // The override populates `redeem_script` AND adds the per-cosigner
        // signatures for the wallet's local seeds (2 local seeds in this
        // fixture, so the returned bundle is fully-signed).
        let signed_bundle = account.clone().pskb_sign(&bundle, wallet_secret.clone(), None, None).await.unwrap();
        let signed_input = &signed_bundle.as_ref()[0].inputs[0];
        let populated_redeem_script =
            signed_input.redeem_script.as_ref().expect("MultiSig::pskb_sign populated redeem_script").clone();

        // Byte-identity against the canonical builder: the slot pubkeys are
        // each cosigner's xpub derived through
        // `multisig_derivation_index / receive / 0` -- the same reduction the
        // operator-Send path applies at `build_multisig_signed_bundle`. The
        // helper's emission must match byte-for-byte or the parent's
        // `multisig_send_extract_*` extract-test family would diverge.
        let xpub_keys = account.xpub_keys().expect("multisig xpubs").clone();
        let multisig_derivation_index = account.clone().as_derivation_capable().unwrap().cosigner_index();
        let mut slot_pubkeys: Vec<secp256k1::PublicKey> = Vec::with_capacity(xpub_keys.len());
        for xpub in xpub_keys.iter() {
            let derived = xpub
                .clone()
                .derive_child(ChildNumber::new(multisig_derivation_index, false).unwrap())
                .unwrap()
                .derive_child(ChildNumber::new(0, false).unwrap())
                .unwrap()
                .derive_child(ChildNumber::new(0, false).unwrap())
                .unwrap();
            slot_pubkeys.push(*derived.public_key());
        }
        let expected_redeem_script =
            multisig_redeem_script(slot_pubkeys.iter().map(|pk| pk.x_only_public_key().0.serialize()), 2).unwrap();
        assert_eq!(populated_redeem_script, expected_redeem_script, "populated redeem_script byte-equals multisig_redeem_script(K=2)");

        // Idempotency: a second invocation on the already-populated bundle
        // preserves the redeem-script (no overwrite). This is the multi-party
        // PSKT exchange invariant -- a downstream cosigner receiving the
        // bundle does not overwrite the upstream cosigner's redeem-script
        // contribution.
        let twice_signed = account.clone().pskb_sign(&signed_bundle, wallet_secret.clone(), None, None).await.unwrap();
        let twice_signed_redeem = twice_signed.as_ref()[0].inputs[0].redeem_script.as_ref().expect("idempotent populate").clone();
        assert_eq!(
            twice_signed_redeem, populated_redeem_script,
            "second pskb_sign preserves the existing redeem_script byte-for-byte"
        );
    }

    /// K-of-N multi-cosigner signing flow produces exactly K signatures per
    /// input. Tests the `(N=2, K=2)` cell directly through
    /// `pskb_signer_for_multisig_cosigner` + accumulate-via-`Input::add` (the
    /// same shape `build_multisig_signed_bundle` uses); the on-chain TXID
    /// dimension is the Validator's gate on the testnet substrate.
    #[tokio::test]
    async fn multisig_send_local_k_of_n_2_of_2() {
        let mnemonics = make_local_mnemonics(2).await;
        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let account = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![]).await.unwrap();

        let receive_address = account.receive_address().unwrap();
        let script_public_key = pay_to_address_script(&receive_address);
        let utxo =
            kaspa_consensus_core::tx::UtxoEntry { amount: 100_000_000, script_public_key, block_daa_score: 1, is_coinbase: false };
        let input = InputBuilder::default()
            .utxo_entry(utxo)
            .previous_outpoint(kaspa_consensus_core::tx::TransactionOutpoint {
                transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[0xcd; 32]),
                index: 0,
            })
            .sig_op_count(2)
            .build()
            .unwrap();
        let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
        let pskt_inner = pskt_creator.constructor().input(input);
        let mut accumulator = Bundle::from(pskt_inner);

        let multisig: Arc<MultiSig> = account.clone().downcast_arc().expect("account is multisig");
        let prv_key_data_ids = multisig.prv_key_data_ids().as_ref().expect("local cosigner ids").clone();
        let network_id = wallet.network_id().unwrap();
        let xpub_keys_strings: Vec<String> = account.xpub_keys().unwrap().iter().map(|k| k.to_string(Some(KeyPrefix::XPUB))).collect();
        let prv_key_data_store = wallet.store().as_prv_key_data_store().unwrap();
        let multisig_derivation_index = account.clone().as_derivation_capable().unwrap().cosigner_index();

        // Per-cosigner signing with per-input K-cap break-out gate (same shape as `build_multisig_signed_bundle`).
        let k: usize = 2;
        for prv_key_data_id in prv_key_data_ids.iter() {
            let all_full = accumulator.iter().all(|p| p.inputs.iter().all(|i| i.partial_sigs.len() >= k));
            if all_full {
                break;
            }
            let prv_key_data = prv_key_data_store.load_key_data(&wallet_secret, prv_key_data_id).await.unwrap().expect("prv_key_data");
            let this_xpub = prv_key_data.create_xpub(None, MULTISIG_ACCOUNT_KIND.into(), 0).await.unwrap();
            let this_xpub_string = this_xpub.to_string(Some(KeyPrefix::XPUB));
            assert!(xpub_keys_strings.iter().any(|s| s == &this_xpub_string), "cosigner xpub present in multisig set");
            let per_cosigner_bundle = pskb_signer_for_multisig_cosigner(
                &accumulator,
                account.clone(),
                &prv_key_data,
                None,
                multisig_derivation_index,
                network_id,
            )
            .await
            .unwrap();
            for (pskt_idx, signed_pskt_inner) in per_cosigner_bundle.0.into_iter().enumerate() {
                for (input_idx, signed_input) in signed_pskt_inner.inputs.into_iter().enumerate() {
                    let accum_input = std::mem::take(&mut accumulator.0[pskt_idx].inputs[input_idx]);
                    accumulator.0[pskt_idx].inputs[input_idx] = (accum_input + signed_input).unwrap();
                }
            }
        }

        assert_eq!(accumulator.0.len(), 1, "single PSKT in bundle");
        assert_eq!(accumulator.0[0].inputs.len(), 1, "single input per PSKT");
        assert_eq!(accumulator.0[0].inputs[0].partial_sigs.len(), k, "exactly K=2 signatures per input post-multi-cosigner sign");
    }

    /// Round-trips a K-of-N multisig with `locals` local cosigner seeds and
    /// `externals` external xpubs (derived from in-session mnemonics) through
    /// sign / finalize / extract on a synthetic PSKT. The extractor invokes the
    /// consensus `TxScriptEngine` on every input, so passing this helper proves
    /// the assembled signature script verifies under the multisig redeem-script's
    /// `OpCheckMultiSig` at consensus rules -- the load-bearing property
    /// `multisig_send_local_k_of_n_2_of_2` does not pin (it asserts only
    /// `partial_sigs.len() == K` and never finalizes). The per-cell wrappers
    /// below close the structural REPL-vs-integration coverage gap across the
    /// full validation matrix and negatively-key against per-cosigner-position
    /// BIP-32 derivation: a signer that derives each cosigner's signing key off
    /// the cosigner's positional index rather than the multisig account's
    /// persisted derivation index produces signing keys whose pubkey does not
    /// match the redeem-script slot the cosigner occupies, returning `EvalFalse`
    /// at extract time.
    async fn run_multisig_send_extract_for_cell(locals: usize, externals: usize, k: u16) {
        let n_total = locals + externals;
        assert!(n_total >= k as usize, "(N={n_total}, K={k}) violates K <= N");
        let mnemonics = make_local_mnemonics(n_total).await;
        let local_mnemonics: Vec<Mnemonic> = mnemonics[..locals].to_vec();
        let external_mnemonics: &[Mnemonic] = &mnemonics[locals..];
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = local_mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let mut external_xpubs: Vec<String> = Vec::with_capacity(externals);
        for em in external_mnemonics.iter() {
            external_xpubs.push(external_xpub_for_testnet(em.phrase()).await);
        }

        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let account = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, k, external_xpubs).await.unwrap();

        let multisig: Arc<MultiSig> = account.clone().downcast_arc().expect("account is multisig");
        let prv_key_data_ids = multisig.prv_key_data_ids().as_ref().expect("local cosigner ids").clone();
        let network_id = wallet.network_id().unwrap();
        let xpub_keys = account.xpub_keys().expect("multisig xpubs").clone();
        assert_eq!(xpub_keys.len(), n_total, "multisig has N cosigner xpubs");
        let multisig_derivation_index = account.clone().as_derivation_capable().unwrap().cosigner_index();

        // Build the receive[0] redeem-script externally by walking each cosigner xpub
        // through the same unhardened tail (`multisig_derivation_index / receive / 0`)
        // the `AddressDerivationManager` uses for the multisig's receive[0]. The synthetic
        // UTXO's `script_pub_key` is the P2SH commitment to that redeem-script; consensus
        // verifies the assembled signature script against it at `extract_tx`.
        let mut receive_pubkeys: Vec<secp256k1::PublicKey> = Vec::with_capacity(xpub_keys.len());
        for xpub in xpub_keys.iter() {
            let derived = xpub
                .clone()
                .derive_child(ChildNumber::new(multisig_derivation_index, false).unwrap())
                .unwrap()
                .derive_child(ChildNumber::new(0, false).unwrap())
                .unwrap()
                .derive_child(ChildNumber::new(0, false).unwrap())
                .unwrap();
            receive_pubkeys.push(*derived.public_key());
        }
        let redeem_script = multisig_redeem_script(receive_pubkeys.iter().map(|pk| pk.x_only_public_key().0.serialize()), k as usize)
            .expect("redeem script");
        let script_public_key = pay_to_script_hash_script(redeem_script.as_slice());

        // Sanity-check: the externally-derived script_public_key matches the multisig's
        // actual receive[0] address. Asserts the address-derivation pipeline reads the
        // multisig at the persisted derivation index, the same value driving signing below.
        let receive_address = account.receive_address().unwrap();
        let receive_script = pay_to_address_script(&receive_address);
        assert_eq!(
            script_public_key, receive_script,
            "(N={n_total}, K={k}) externally-derived redeem-script's P2SH must match the multisig's receive[0] address",
        );

        let utxo =
            kaspa_consensus_core::tx::UtxoEntry { amount: 100_000_000, script_public_key, block_daa_score: 1, is_coinbase: false };
        let input = InputBuilder::default()
            .utxo_entry(utxo)
            .previous_outpoint(kaspa_consensus_core::tx::TransactionOutpoint {
                transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[0xee; 32]),
                index: 0,
            })
            .sig_op_count(n_total as u8)
            .redeem_script(redeem_script)
            .build()
            .unwrap();
        let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
        let pskt_inner = pskt_creator.constructor().input(input);
        let mut accumulator = Bundle::from(pskt_inner);

        let k_usize = k as usize;
        let prv_key_data_store = wallet.store().as_prv_key_data_store().unwrap();
        for prv_key_data_id in prv_key_data_ids.iter() {
            let all_full = accumulator.iter().all(|p| p.inputs.iter().all(|i| i.partial_sigs.len() >= k_usize));
            if all_full {
                break;
            }
            let prv_key_data =
                prv_key_data_store.load_key_data(&wallet_secret, prv_key_data_id).await.unwrap().expect("prv_key_data loaded");
            let per_cosigner_bundle = pskb_signer_for_multisig_cosigner(
                &accumulator,
                account.clone(),
                &prv_key_data,
                None,
                multisig_derivation_index,
                network_id,
            )
            .await
            .unwrap();
            for (pskt_idx, signed_pskt_inner) in per_cosigner_bundle.0.into_iter().enumerate() {
                for (input_idx, signed_input) in signed_pskt_inner.inputs.into_iter().enumerate() {
                    let accum_input = std::mem::take(&mut accumulator.0[pskt_idx].inputs[input_idx]);
                    accumulator.0[pskt_idx].inputs[input_idx] = (accum_input + signed_input).unwrap();
                }
            }
        }

        assert_eq!(accumulator.0[0].inputs[0].partial_sigs.len(), k_usize, "(N={n_total}, K={k}) exactly K signatures accumulated",);

        // Finalize, then extract -- the extractor runs `TxScriptEngine::execute()` per
        // input. With per-cosigner-position derivation `extract_tx` would return
        // Err(EvalFalse) because at least one signing key's pubkey would not match the
        // redeem-script slot the cosigner occupies. With every cosigner deriving at the
        // shared multisig derivation index, signatures verify, and `extract_tx` returns Ok.
        let signer_pskt: PSKT<kaspa_wallet_pskt::pskt::Signer> =
            PSKT::<kaspa_wallet_pskt::pskt::Signer>::from(accumulator.0[0].clone());
        let finalizer_pskt = signer_pskt.finalizer();
        let finalized = finalize_pskt_one_or_more_sig_and_redeem_script(finalizer_pskt).expect("finalize");
        let extractor = finalized.extractor().expect("extractor: finalized PSKT yields an extractor");
        let params = Params::from(network_id);
        let extract_result = extractor.extract_tx(&params);
        assert!(
            extract_result.is_ok(),
            "(N={n_total}, K={k}) extract_tx must succeed under consensus script verify; got {extract_result:?}",
        );
    }

    // Per-cell wrappers exercising the lead-named multisig validation matrix. Each cell
    // closes the same structural REPL-vs-integration coverage gap on a different
    // (locals, externals, K) topology; mixed-source cells (externals > 0) pin the
    // create-with-external-xpub path the substrate-class topology exercises.
    //
    // The (1,1) cell is intentionally excluded: at `N = 1`, address derivation in
    // `create_address` takes the single-key P2PK branch and emits a
    // pay-to-pubkey address rather than a P2SH multisig. The helper exercises the
    // `OpCheckMultiSig` consensus-script path, which the (1,1) cell does not reach;
    // covering it requires a different harness shape on the P2PK send path and falls
    // outside the OpCheckMultiSig-slot defect class the call-site derivation-index closes.

    /// (N=2, K=2) cell, all-local cosigners.
    #[tokio::test]
    async fn multisig_send_extract_2_of_2() {
        run_multisig_send_extract_for_cell(2, 0, 2).await;
    }

    /// (N=3, K=2) cell, 2 local + 1 external xpub.
    #[tokio::test]
    async fn multisig_send_extract_2_of_3_mixed_external() {
        run_multisig_send_extract_for_cell(2, 1, 2).await;
    }

    /// (N=4, K=2) cell, 2 local + 2 external xpubs.
    #[tokio::test]
    async fn multisig_send_extract_2_of_4_mixed_external() {
        run_multisig_send_extract_for_cell(2, 2, 2).await;
    }

    /// (N=5, K=3) cell, 3 local + 2 external xpubs.
    #[tokio::test]
    async fn multisig_send_extract_3_of_5_mixed_external() {
        run_multisig_send_extract_for_cell(3, 2, 3).await;
    }

    /// (N=6, K=3) cell, 3 local + 3 external xpubs.
    #[tokio::test]
    async fn multisig_send_extract_3_of_6_mixed_external() {
        run_multisig_send_extract_for_cell(3, 3, 3).await;
    }

    /// Drives an 8-of-15 multisig (8 local seeds + 7 external xpubs) end-to-end
    /// through the same production PSKT-construction path the smaller cells use.
    /// N=15 is the largest Schnorr P2SH cosigner count whose canonical redeem
    /// script fits the consensus `MAX_SCRIPT_ELEMENT_SIZE` PUSHDATA cap (the
    /// `MAX_PUB_KEYS_PER_MUTLTISIG = 20` stack-pubkey cap is looser than the
    /// element-size cap, so the effective Schnorr P2SH limit binds at N=15).
    /// This cell pushes Finalizer reorder over the largest currently-shippable
    /// xpub set.
    #[tokio::test]
    async fn multisig_send_extract_8_of_15_max_p2sh_element_size() {
        run_multisig_send_extract_for_cell(8, 7, 8).await;
    }

    /// Wallet rejects a multisig with cosigner count above the consensus
    /// maximum at account-creation time rather than letting consensus reject
    /// the spend later. Constructing a 222-cosigner account must fail with
    /// `MultisigPubKeyCountExceedsConsensus`; 222 is well above
    /// `kaspa_txscript::MAX_PUB_KEYS_PER_MUTLTISIG` and triggers the guard
    /// inside `normalize_and_merge_xpubs`. The xpubs are cloned from a single
    /// derivation because the guard fires on count alone, not on uniqueness.
    #[tokio::test]
    async fn multisig_create_rejects_pub_key_count_above_consensus_max() {
        let xpub =
            xpub_from_mnemonic_phrase(Mnemonic::random(kaspa_bip32::WordCount::Words24, Language::English).unwrap().phrase()).await;
        let generated_xpubs: Vec<String> = vec![xpub; 222];
        let err = normalize_and_merge_xpubs(Vec::new(), &generated_xpubs, 111, NetworkType::Testnet)
            .expect_err("222-cosigner multisig must be rejected before redeem-script construction");
        match err {
            Error::MultisigPubKeyCountExceedsConsensus { count, max } => {
                assert_eq!(count, 222, "rejection names the supplied N");
                assert_eq!(max, kaspa_txscript::MAX_PUB_KEYS_PER_MUTLTISIG as usize, "rejection names the consensus max");
            }
            other => panic!("expected MultisigPubKeyCountExceedsConsensus, got {other:?}"),
        }
    }

    /// Wallet rejects a multisig whose signature threshold exceeds the
    /// cosigner count (K > N is mathematically unreachable). 45-of-14 must
    /// fail with `MultisigInvalidThreshold`.
    #[tokio::test]
    async fn multisig_create_rejects_threshold_above_cosigner_count() {
        let xpub =
            xpub_from_mnemonic_phrase(Mnemonic::random(kaspa_bip32::WordCount::Words24, Language::English).unwrap().phrase()).await;
        let generated_xpubs: Vec<String> = vec![xpub; 14];
        let err = normalize_and_merge_xpubs(Vec::new(), &generated_xpubs, 45, NetworkType::Testnet)
            .expect_err("45-of-14 must be rejected before redeem-script construction");
        match err {
            Error::MultisigInvalidThreshold { k, n } => {
                assert_eq!(k, 45, "rejection names the supplied K");
                assert_eq!(n, 14, "rejection names the supplied N");
            }
            other => panic!("expected MultisigInvalidThreshold, got {other:?}"),
        }
    }

    /// Wallet rejects every cosigner count whose Schnorr P2SH redeem script
    /// exceeds the consensus `MAX_SCRIPT_ELEMENT_SIZE` PUSHDATA cap. The
    /// canonical script length is `K_bytes + 33*N + N_bytes + 1` where K and
    /// N use the small-int opcode (1 byte) for values 1..=16 and the
    /// one-byte PUSHDATA form (2 bytes) for 17..=20. Every cosigner count in
    /// {16, 17, 18, 19, 20} stays inside `MAX_PUB_KEYS_PER_MUTLTISIG` but
    /// exceeds the 520-byte PUSHDATA cap. The wallet must refuse at
    /// creation time rather than letting `ScriptBuilder::add_data` panic
    /// later during script_sig assembly.
    #[tokio::test]
    async fn multisig_create_rejects_redeem_script_above_element_size_at_each_boundary_n() {
        let xpub =
            xpub_from_mnemonic_phrase(Mnemonic::random(kaspa_bip32::WordCount::Words24, Language::English).unwrap().phrase()).await;
        // Predicted sizes for K=1: N=16 -> 1+528+1+1=531; N=17 -> 1+561+2+1=565;
        // N=18 -> 1+594+2+1=598; N=19 -> 1+627+2+1=631; N=20 -> 1+660+2+1=664.
        let cells: &[(usize, usize)] = &[(16, 531), (17, 565), (18, 598), (19, 631), (20, 664)];
        for &(n, expected_size) in cells {
            let generated_xpubs: Vec<String> = vec![xpub.clone(); n];
            let err = normalize_and_merge_xpubs(Vec::new(), &generated_xpubs, 1, NetworkType::Testnet)
                .expect_err("Schnorr multisig at boundary N must reject (redeem script exceeds element-size cap)");
            match err {
                Error::MultisigRedeemScriptExceedsElementSize { size, max } => {
                    assert_eq!(size, expected_size, "N={n}: rejection names the predicted redeem-script size");
                    assert_eq!(max, kaspa_txscript::MAX_SCRIPT_ELEMENT_SIZE, "N={n}: rejection names the consensus element-size cap");
                }
                other => panic!("N={n}: expected MultisigRedeemScriptExceedsElementSize, got {other:?}"),
            }
        }
    }

    /// Wallet rejects a multisig whose cosigner set contains duplicate xpubs.
    /// Two cosigners sharing an xpub would collapse onto the same redeem-script
    /// slot, letting a single signer satisfy K of those slots and breaking the
    /// K-of-N threshold guarantee. Detection runs after sort so duplicates are
    /// adjacent.
    #[tokio::test]
    async fn multisig_create_rejects_duplicate_xpubs() {
        let xpub =
            xpub_from_mnemonic_phrase(Mnemonic::random(kaspa_bip32::WordCount::Words24, Language::English).unwrap().phrase()).await;
        // Two identical xpubs, K=2 over N=2, well inside the count and element-size guards.
        let generated_xpubs: Vec<String> = vec![xpub.clone(); 2];
        let err = normalize_and_merge_xpubs(Vec::new(), &generated_xpubs, 2, NetworkType::Testnet)
            .expect_err("duplicate-xpub multisig must be rejected at creation time");
        match err {
            Error::MultisigDuplicateXpub { xpub: dup } => {
                assert_eq!(dup, xpub, "rejection names the duplicate xpub");
            }
            other => panic!("expected MultisigDuplicateXpub, got {other:?}"),
        }
    }

    /// Cross-check `predicted_schnorr_redeem_script_size` against the byte
    /// length the canonical builder `kaspa_txscript::multisig_redeem_script`
    /// emits for the same (K, N). If the helper drifts from the canonical
    /// encoding the on-disk wallet would accept parameters that fail later
    /// at extract, undoing the consensus guard.
    #[tokio::test]
    async fn predicted_schnorr_redeem_script_size_matches_canonical_builder() {
        use kaspa_txscript::multisig_redeem_script;
        // Cells span the small-int boundary (K, N <= 16) and the PUSHDATA
        // boundary (17..=20). Pubkey bytes are synthetic: the canonical
        // builder treats them as opaque 32-byte pushdatas.
        let cells: &[(u16, usize)] =
            &[(1, 1), (2, 2), (1, 16), (16, 16), (1, 17), (13, 17), (1, 20), (20, 20), (3, 5), (8, 15), (15, 15)];
        for &(k, n) in cells {
            let pubkeys: Vec<[u8; 32]> = (0u8..n as u8).map(|i| [i; 32]).collect();
            let actual = multisig_redeem_script(pubkeys.iter().copied(), k as usize).expect("canonical redeem script");
            let predicted = predicted_schnorr_redeem_script_size(k, n);
            assert_eq!(actual.len(), predicted, "predicted size must match canonical builder output for {k}-of-{n}");
        }
    }

    /// Cross-network xpub rejection at the construction-time gate.
    /// Parametrized across the four mismatched cells of the kaspa-network
    /// accept-list (Mainnet wants KPUB, Testnet wants KTUB; the four
    /// non-matching kaspa or canonical XPUB combinations are rejected)
    /// plus the foreign-network cases (TPUB, YPUB). For each cell
    /// `normalize_and_merge_xpubs` must return
    /// `Error::MultisigXpubNetworkMismatch` naming the supplied prefix
    /// and the wallet network; the helper is the contract surface both
    /// `Wallet::create_account_multisig` and
    /// `Wallet::import_multisig_with_mnemonic` route through, so a single
    /// helper-level parametric covers both API paths.
    #[tokio::test]
    async fn multisig_create_rejects_cross_network_xpub() {
        let canonical =
            xpub_from_mnemonic_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
                .await;
        let cells: &[(NetworkType, KeyPrefix)] = &[
            (NetworkType::Mainnet, KeyPrefix::KTUB),
            (NetworkType::Testnet, KeyPrefix::KPUB),
            (NetworkType::Mainnet, KeyPrefix::XPUB),
            (NetworkType::Testnet, KeyPrefix::XPUB),
            (NetworkType::Mainnet, KeyPrefix::TPUB),
            (NetworkType::Testnet, KeyPrefix::YPUB),
        ];
        let generated_xpub =
            xpub_from_mnemonic_phrase("legal winner thank year wave sausage worth useful legal winner thank yellow").await;
        let mut generated_xpubs = vec![generated_xpub];
        generated_xpubs.sort_unstable();
        for &(wallet_network, supplied) in cells {
            let mut reprefixed = kaspa_bip32::ExtendedKey::from_str(&canonical).unwrap();
            reprefixed.prefix = supplied;
            let user_xpub = reprefixed.to_string();
            let err = normalize_and_merge_xpubs(vec![user_xpub], &generated_xpubs, 2, wallet_network)
                .expect_err("cross-network or foreign-prefix user-supplied xpub must reject");
            match err {
                Error::MultisigXpubNetworkMismatch { supplied_prefix, wallet_network: rejected_for } => {
                    assert_eq!(
                        supplied_prefix, supplied,
                        "({wallet_network:?}, {supplied:?}) cell: rejection names the supplied prefix"
                    );
                    assert_eq!(
                        rejected_for, wallet_network,
                        "({wallet_network:?}, {supplied:?}) cell: rejection names the wallet network"
                    );
                }
                other => panic!("({wallet_network:?}, {supplied:?}) cell: expected MultisigXpubNetworkMismatch, got {other:?}"),
            }
        }
    }

    /// Cross-network accept path: network-discriminating kaspa prefix matching
    /// the wallet network passes the gate. Pairs the create/import-side
    /// reject coverage above with the two same-network success cells.
    #[tokio::test]
    async fn multisig_accept_same_network_kaspa_xpub() {
        let canonical =
            xpub_from_mnemonic_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
                .await;
        let generated_xpub =
            xpub_from_mnemonic_phrase("legal winner thank year wave sausage worth useful legal winner thank yellow").await;
        let mut generated_xpubs = vec![generated_xpub];
        generated_xpubs.sort_unstable();
        let cells: &[(NetworkType, KeyPrefix)] = &[(NetworkType::Mainnet, KeyPrefix::KPUB), (NetworkType::Testnet, KeyPrefix::KTUB)];
        for &(wallet_network, accepted) in cells {
            let mut reprefixed = kaspa_bip32::ExtendedKey::from_str(&canonical).unwrap();
            reprefixed.prefix = accepted;
            let user_xpub = reprefixed.to_string();
            let result = normalize_and_merge_xpubs(vec![user_xpub], &generated_xpubs, 2, wallet_network);
            assert!(result.is_ok(), "({wallet_network:?}, {accepted:?}) cell: accept path must succeed, got {result:?}");
            // Output preserves the count and contains XPUB-canonical entries.
            let output = result.unwrap();
            assert_eq!(output.len(), 2, "two cosigner entries after merge");
            assert!(output.iter().all(|s| s.starts_with("xpub")), "every entry stored in canonical XPUB form");
        }
    }

    /// Cross-network end-to-end at the `Wallet::import_multisig_with_mnemonic`
    /// API surface: rejection of a cross-network user-supplied xpub
    /// propagates through the wallet's import wizard to the same error
    /// variant the helper raises, with the supplied_prefix and
    /// wallet_network fields populated from the caller context.
    #[tokio::test]
    async fn multisig_import_rejects_cross_network_xpub_at_api() {
        let mnemonics = make_local_mnemonics(2).await;
        let canonical =
            xpub_from_mnemonic_phrase("abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about")
                .await;

        // Wallet is Testnet; KPUB user-supplied xpub is the wrong-network case.
        let mut reprefixed_kpub = kaspa_bip32::ExtendedKey::from_str(&canonical).unwrap();
        reprefixed_kpub.prefix = KeyPrefix::KPUB;
        let user_xpub_kpub = reprefixed_kpub.to_string();

        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let result = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![user_xpub_kpub]).await;
        match result {
            Ok(_) => panic!("KPUB external xpub on Testnet wallet must reject at import-time"),
            Err(Error::MultisigXpubNetworkMismatch { supplied_prefix, wallet_network }) => {
                assert_eq!(supplied_prefix, KeyPrefix::KPUB);
                assert_eq!(wallet_network, NetworkType::Testnet);
            }
            Err(other) => panic!("expected MultisigXpubNetworkMismatch, got {other:?}"),
        }
    }

    /// Derive `n` distinct KTUB-prefixed external xpubs for the Testnet
    /// test wallet. Each xpub comes from a fresh random mnemonic so the
    /// returned set is unique, mirroring how the wizard would receive
    /// distinct external cosigner xpubs at user-input time.
    async fn external_xpubs_for_testnet(n: usize) -> Vec<String> {
        let mnemonics = make_local_mnemonics(n).await;
        let mut xpubs = Vec::with_capacity(n);
        for mnemonic in mnemonics {
            xpubs.push(external_xpub_for_testnet(mnemonic.phrase()).await);
        }
        xpubs
    }

    /// Import-path mirror of `multisig_create_rejects_pub_key_count_above_consensus_max`.
    /// One local mnemonic plus `MAX_PUB_KEYS_PER_MUTLTISIG` external xpubs
    /// lifts the merged cosigner count one above the consensus
    /// stack-pubkey-count cap. The wallet import API must surface the same
    /// `MultisigPubKeyCountExceedsConsensus` the helper raises on the create
    /// path.
    #[tokio::test]
    async fn multisig_import_rejects_pub_key_count_above_consensus_max() {
        const CONSENSUS_CAP: usize = kaspa_txscript::MAX_PUB_KEYS_PER_MUTLTISIG as usize;
        const OVER_CAP_TOTAL: usize = CONSENSUS_CAP + 1;
        let mnemonics = make_local_mnemonics(1).await;
        let externals = external_xpubs_for_testnet(OVER_CAP_TOTAL - mnemonics.len()).await;

        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let result = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, externals).await;
        match result {
            Err(Error::MultisigPubKeyCountExceedsConsensus { count, max }) => {
                assert_eq!(count, OVER_CAP_TOTAL, "rejection names the merged cosigner count");
                assert_eq!(max, CONSENSUS_CAP, "rejection names the consensus max");
            }
            Ok(_) => panic!("over-cap import must reject"),
            Err(other) => panic!("expected MultisigPubKeyCountExceedsConsensus, got {other:?}"),
        }
    }

    /// Import-path mirror of `multisig_create_rejects_threshold_above_cosigner_count`.
    /// A 3-of-2 (`min_sigs > N`) threshold is mathematically unreachable;
    /// the wallet import API must reject with `MultisigInvalidThreshold`.
    #[tokio::test]
    async fn multisig_import_rejects_threshold_above_cosigner_count() {
        let mnemonics = make_local_mnemonics(1).await;
        let externals = external_xpubs_for_testnet(1).await;

        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let result = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 3, externals).await;
        match result {
            Err(Error::MultisigInvalidThreshold { k, n }) => {
                assert_eq!(k, 3, "rejection names the supplied K");
                assert_eq!(n, 2, "rejection names the merged cosigner count");
            }
            Ok(_) => panic!("3-of-2 import must reject"),
            Err(other) => panic!("expected MultisigInvalidThreshold, got {other:?}"),
        }
    }

    /// Import-path mirror of
    /// `multisig_create_rejects_redeem_script_above_element_size_at_each_boundary_n`.
    /// At N=16 the predicted Schnorr redeem script is 531 bytes, above the
    /// consensus `MAX_SCRIPT_ELEMENT_SIZE = 520` PUSHDATA cap. The wallet
    /// import API must refuse rather than letting `ScriptBuilder::add_data`
    /// fail later during script_sig assembly.
    #[tokio::test]
    async fn multisig_import_rejects_redeem_script_above_element_size() {
        let mnemonics = make_local_mnemonics(1).await;
        let externals = external_xpubs_for_testnet(15).await;

        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let result = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 1, externals).await;
        match result {
            Err(Error::MultisigRedeemScriptExceedsElementSize { size, max }) => {
                assert_eq!(size, 531, "N=16 K=1: rejection names the predicted redeem-script size");
                assert_eq!(max, kaspa_txscript::MAX_SCRIPT_ELEMENT_SIZE, "rejection names the consensus element-size cap");
            }
            Ok(_) => panic!("N=16 import must reject (redeem script exceeds element-size cap)"),
            Err(other) => panic!("expected MultisigRedeemScriptExceedsElementSize, got {other:?}"),
        }
    }

    /// Import-path mirror of `multisig_create_rejects_duplicate_xpubs`. A
    /// mnemonic and an external xpub that re-derives the same key (the
    /// canonical form of the mnemonic's multisig xpub, re-prefixed to
    /// KTUB so it passes the cross-network gate) collapse to the same
    /// redeem-script slot after canonicalization. The wallet import API
    /// must reject so a single signer cannot satisfy K of those slots and
    /// silently weaken the K-of-N threshold guarantee.
    #[tokio::test]
    async fn multisig_import_rejects_duplicate_xpubs() {
        let mnemonic = make_local_mnemonics(1).await.pop().unwrap();
        let prv_key_data = PrvKeyData::try_new_from_mnemonic(mnemonic.clone(), None, EncryptionKind::XChaCha20Poly1305).unwrap();
        let generated_xpub = prv_key_data.create_xpub(None, MULTISIG_ACCOUNT_KIND.into(), 0).await.unwrap();
        let canonical = generated_xpub.to_string(Some(KeyPrefix::XPUB));
        let mut reprefixed = ExtendedKey::from_str(&canonical).unwrap();
        reprefixed.prefix = KeyPrefix::KTUB;
        let external = reprefixed.to_string();

        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let result = wallet.import_multisig_with_mnemonic(&wallet_secret, vec![(mnemonic, None)], 1, vec![external]).await;
        match result {
            Err(Error::MultisigDuplicateXpub { xpub: dup }) => {
                assert_eq!(dup, canonical, "rejection names the duplicate xpub in canonical XPUB form");
            }
            Ok(_) => panic!("import with duplicate xpub must reject"),
            Err(other) => panic!("expected MultisigDuplicateXpub, got {other:?}"),
        }
    }

    /// All six construction-time guards (cross-network xpub, duplicate
    /// xpub, threshold K=0, threshold K>N, count cap N>20, redeem-script
    /// element-size cap at N=16 Schnorr) MUST fire when
    /// `Wallet::create_account_multisig` is invoked with no local cosigner
    /// seeds (`prv_key_data_args.is_empty()`) -- the all-external-cosigner
    /// path that the wizard exposes when the operator answers 0 to the
    /// "number of private keys to generate" prompt. Without the unified
    /// helper call the wallet silently persists multisig accounts that
    /// the consensus engine would reject at first spend.
    #[tokio::test]
    async fn multisig_create_with_no_local_seeds_enforces_guards() {
        let wallet_secret = Secret::new(vec![]);

        // Cell 1 -- cross-network xpub. A canonical-stripped XPUB is
        // ambiguous about its origin network and the helper rejects it
        // on every wallet network.
        {
            let wallet = test_wallet().await;
            let canonical = xpub_from_mnemonic_phrase(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            )
            .await;
            let valid_ktub =
                external_xpub_for_testnet("legal winner thank year wave sausage worth useful legal winner thank yellow").await;
            let result = wallet.create_account_multisig(&wallet_secret, Vec::new(), vec![canonical, valid_ktub], None, 2).await;
            match result {
                Err(Error::MultisigXpubNetworkMismatch { supplied_prefix, wallet_network }) => {
                    assert_eq!(supplied_prefix, KeyPrefix::XPUB, "rejection names the supplied prefix");
                    assert_eq!(wallet_network, NetworkType::Testnet, "rejection names the wallet network");
                }
                Ok(_) => panic!("watch-only create with canonical XPUB on Testnet must reject"),
                Err(other) => panic!("expected MultisigXpubNetworkMismatch, got {other:?}"),
            }
        }

        // Cell 2 -- duplicate xpub. Two identical KTUB-prefixed entries
        // collapse to the same redeem-script slot after canonicalization.
        {
            let wallet = test_wallet().await;
            let ext = external_xpub_for_testnet(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            )
            .await;
            let result = wallet.create_account_multisig(&wallet_secret, Vec::new(), vec![ext.clone(), ext], None, 2).await;
            match result {
                Err(Error::MultisigDuplicateXpub { xpub }) => {
                    assert!(xpub.starts_with("xpub"), "duplicate reported in canonical XPUB form, got: {xpub}");
                }
                Ok(_) => panic!("watch-only create with duplicate xpub must reject"),
                Err(other) => panic!("expected MultisigDuplicateXpub, got {other:?}"),
            }
        }

        // Cell 3 -- threshold K=0. The threshold check is reached after
        // the cross-network and count caps; supply two valid distinct
        // KTUB entries so only K=0 trips the guard.
        {
            let wallet = test_wallet().await;
            let externals = external_xpubs_for_testnet(2).await;
            let result = wallet.create_account_multisig(&wallet_secret, Vec::new(), externals, None, 0).await;
            match result {
                Err(Error::MultisigInvalidThreshold { k, n }) => {
                    assert_eq!(k, 0, "rejection names the supplied K");
                    assert_eq!(n, 2, "rejection names the cosigner count");
                }
                Ok(_) => panic!("watch-only create with K=0 must reject"),
                Err(other) => panic!("expected MultisigInvalidThreshold, got {other:?}"),
            }
        }

        // Cell 4 -- threshold K>N. Two distinct KTUB cosigners with K=3
        // is mathematically unreachable.
        {
            let wallet = test_wallet().await;
            let externals = external_xpubs_for_testnet(2).await;
            let result = wallet.create_account_multisig(&wallet_secret, Vec::new(), externals, None, 3).await;
            match result {
                Err(Error::MultisigInvalidThreshold { k, n }) => {
                    assert_eq!(k, 3, "rejection names the supplied K");
                    assert_eq!(n, 2, "rejection names the cosigner count");
                }
                Ok(_) => panic!("watch-only create with K=3 N=2 must reject"),
                Err(other) => panic!("expected MultisigInvalidThreshold, got {other:?}"),
            }
        }

        // Cell 5 -- count cap. One cosigner above the consensus
        // stack-pubkey-count cap must reject.
        {
            const CONSENSUS_CAP: usize = kaspa_txscript::MAX_PUB_KEYS_PER_MUTLTISIG as usize;
            const OVER_CAP_TOTAL: usize = CONSENSUS_CAP + 1;
            let wallet = test_wallet().await;
            let externals = external_xpubs_for_testnet(OVER_CAP_TOTAL).await;
            let result = wallet.create_account_multisig(&wallet_secret, Vec::new(), externals, None, 2).await;
            match result {
                Err(Error::MultisigPubKeyCountExceedsConsensus { count, max }) => {
                    assert_eq!(count, OVER_CAP_TOTAL, "rejection names the cosigner count");
                    assert_eq!(max, CONSENSUS_CAP, "rejection names the consensus max");
                }
                Ok(_) => panic!("watch-only create above consensus cap must reject"),
                Err(other) => panic!("expected MultisigPubKeyCountExceedsConsensus, got {other:?}"),
            }
        }

        // Cell 6 -- size cap N=16 Schnorr. Sixteen distinct KTUB cosigners
        // produce a 531-byte Schnorr P2SH redeem script that exceeds the
        // consensus 520-byte PUSHDATA cap.
        {
            let wallet = test_wallet().await;
            let externals = external_xpubs_for_testnet(16).await;
            let result = wallet.create_account_multisig(&wallet_secret, Vec::new(), externals, None, 1).await;
            match result {
                Err(Error::MultisigRedeemScriptExceedsElementSize { size, max }) => {
                    assert_eq!(size, 531, "N=16 K=1: rejection names the predicted redeem-script size");
                    assert_eq!(max, kaspa_txscript::MAX_SCRIPT_ELEMENT_SIZE, "rejection names the consensus element-size cap");
                }
                Ok(_) => panic!("watch-only create with N=16 must reject (redeem script exceeds element-size cap)"),
                Err(other) => panic!("expected MultisigRedeemScriptExceedsElementSize, got {other:?}"),
            }
        }
    }

    /// Drives a 2-of-3 multisig (2 local seeds + 1 external xpub) end-to-end through
    /// the production PSKT-construction path: `Generator` -> `PSKTGenerator` ->
    /// `bundle_from_pskt_generator` -> `convert.rs::Inner::try_from`. The conversion
    /// path constructs PSKT inputs with `redeem_script: None` (it has no Account-aware
    /// branch); without `redeem_script`, the Finalizer's `Some` branch is never
    /// reached, the `None` branch emits a `script_sig` with no trailing redeem-script
    /// push, and consensus-script-verify fails the P2SH BLAKE2B check at extract,
    /// returning `Err(EvalFalse)`.
    ///
    /// The 5 parametrized cells in the matrix above bypass this code path by constructing
    /// PSKTs via `InputBuilder::default().redeem_script(...).build()` directly -- they
    /// exercise the Finalizer's `Some` branch in isolation but skip the
    /// production conversion. This test closes the structural coverage gap by going
    /// through the production conversion path. Without per-input `redeem_script`
    /// population the extract returns `Err(EvalFalse)`; with the redeem_script
    /// population in `build_multisig_signed_bundle` running between
    /// `bundle_from_pskt_generator` and the per-cosigner sign loop, the
    /// Finalizer's `Some` branch assembles a consensus-clean P2SH-multisig
    /// `script_sig`, and `extract_tx` returns `Ok`.
    #[tokio::test]
    async fn multisig_send_extract_via_pskt_generator_2_of_3_mixed_external() {
        use crate::account::variants::multisig::build_multisig_signed_bundle;
        use crate::tx::{Fees, GeneratorSettings, PaymentDestination, PaymentOutputs};
        use crate::utils::kaspa_to_sompi;
        use crate::utxo::UtxoEntryReference;

        let mnemonics = make_local_mnemonics(3).await;
        let local_a = mnemonics[0].clone();
        let local_b = mnemonics[1].clone();
        let external_xpub = external_xpub_for_testnet(mnemonics[2].phrase()).await;

        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = vec![(local_a, None), (local_b, None)];
        let account =
            wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![external_xpub]).await.unwrap();

        let multisig: Arc<MultiSig> = account.clone().downcast_arc().expect("account is multisig");
        let prv_key_data_ids: Vec<PrvKeyDataId> = multisig.prv_key_data_ids().as_ref().expect("local cosigner ids").as_ref().clone();
        let xpub_keys = account.xpub_keys().expect("multisig xpubs").clone();
        let xpub_keys_strings: Vec<String> = xpub_keys.iter().map(|k| k.to_string(Some(KeyPrefix::XPUB))).collect();
        let network_id = wallet.network_id().unwrap();

        // Synthetic UTXO at the multisig's receive[0] address; `simulated_with_address`
        // sets `script_public_key = pay_to_address_script(&receive_address)`, the same
        // P2SH script the multisig commits to.
        let receive_address = account.receive_address().unwrap();
        let amount: u64 = kaspa_to_sompi(10.0);
        let utxo_entry = UtxoEntryReference::simulated_with_address(amount, &receive_address);

        // Destination address (a fixed testnet payment target). The Generator selects the
        // single available UTXO as input and produces a payment-plus-change transaction.
        let destination_address =
            Address::try_from("kaspatest:qqrewmx4gpuekvk8grenkvj2hp7xt0c35rxgq383f6gy223c4ud5s58ptm6er").unwrap();
        let payment_outputs: PaymentOutputs = (&[(destination_address, kaspa_to_sompi(1.0))] as &[(Address, u64)]).into();
        let final_destination: PaymentDestination = payment_outputs.into();

        // GeneratorSettings is built directly (mirrors `make_generator` in
        // `tx/generator/test.rs`) so the test does not depend on a populated UtxoContext.
        // sig_op_count = N (multisig); minimum_signatures = K; change_address routes back
        // to the multisig's receive[0]. The single UTXO is delivered via the iterator.
        let utxo_iter: Box<dyn Iterator<Item = UtxoEntryReference> + Send + Sync + 'static> = Box::new(std::iter::once(utxo_entry));
        let settings = GeneratorSettings {
            network_id,
            multiplexer: None,
            sig_op_count: xpub_keys.len() as u8,
            minimum_signatures: 2,
            change_address: receive_address.clone(),
            utxo_iterator: utxo_iter,
            source_utxo_context: None,
            priority_utxo_entries: None,
            destination_utxo_context: None,
            fee_rate: None,
            final_transaction_priority_fee: Fees::SenderPays(kaspa_to_sompi(0.001)),
            final_transaction_destination: final_destination,
            final_transaction_payload: None,
        };

        let abortable = Abortable::default();
        let (bundle, _summary) = build_multisig_signed_bundle(
            account.clone(),
            xpub_keys_strings,
            prv_key_data_ids,
            2,
            settings,
            wallet_secret,
            None,
            &abortable,
            None,
        )
        .await
        .expect("build_multisig_signed_bundle: signed bundle through production conversion path");

        assert!(!bundle.0.is_empty(), "bundle has at least one PSKT");
        for pskt_inner in bundle.0.iter() {
            for input in pskt_inner.inputs.iter() {
                assert!(
                    input.redeem_script.is_some(),
                    "every input populates redeem_script via the population block in build_multisig_signed_bundle",
                );
                assert_eq!(input.partial_sigs.len(), 2, "exactly K=2 signatures per input");
            }
        }

        // Finalize and extract every PSKT in the bundle. The extractor invokes
        // `TxScriptEngine::execute()` per input. Without per-input `redeem_script`
        // population the conversion-path bundle has `redeem_script: None`, the
        // Finalizer's `None` branch emits a malformed `script_sig`, and `extract_tx`
        // returns `Err(EvalFalse)`. With `redeem_script` populated every input carries
        // it, the Finalizer's `Some` branch assembles a consensus-clean
        // P2SH-multisig `script_sig`, and `extract_tx` returns `Ok`.
        let params = Params::from(network_id);
        for pskt_inner in bundle.0.into_iter() {
            let signer_pskt: PSKT<kaspa_wallet_pskt::pskt::Signer> = PSKT::<kaspa_wallet_pskt::pskt::Signer>::from(pskt_inner);
            let finalizer_pskt = signer_pskt.finalizer();
            let finalized = finalize_pskt_one_or_more_sig_and_redeem_script(finalizer_pskt).expect("finalize");
            let extractor = finalized.extractor().expect("extractor: finalized PSKT yields an extractor");
            let extract_result = extractor.extract_tx(&params);
            assert!(extract_result.is_ok(), "extract_tx must succeed via the production PSKT-conversion path; got {extract_result:?}",);
        }
    }

    /// Pins the wallet-level encryption query against multi-id accounts.
    /// The trait-default single-key accessor `Account::prv_key_data_id` is
    /// intentionally unimplemented on multisig (a multisig has 0..N local
    /// keys, not exactly one), so the encryption query MUST iterate the
    /// `AssocPrvKeyDataIds` set rather than dereferencing the single-key
    /// surface. Asserts `is_account_key_encrypted` returns `Some(false)`
    /// for a multisig imported with unencrypted local cosigner keys.
    #[tokio::test]
    async fn multisig_account_encryption_query_returns_unencrypted() {
        let mnemonics = make_local_mnemonics(2).await;
        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let account = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![]).await.unwrap();

        let result = wallet.is_account_key_encrypted(&account).await.expect("multi-id account encryption query succeeds");
        assert_eq!(result, Some(false), "unencrypted local cosigner keys yield Some(false)");
    }

    /// A 1-of-1 multisig account (1 cosigner xpub, 1 local mnemonic, Schnorr)
    /// derives a P2PK receive address. Per `Address` in
    /// `libkaspawallet/keypair.go` (1-of-1 branch returns `p2pkAddress`), the
    /// Go-wallet derives P2PK at single-cosigner count; rusty-kaspa matches
    /// via `derivation::create_address` `keys.len() <= 1` branch. The P2PK
    /// address shape is the precondition for the single-signature
    /// send-routing branch in `MultiSig::send` / `sweep` /
    /// `pskb_from_send_generator`; a derived `Version::ScriptHash` would put
    /// the routing fix on the wrong branch and trip `OpCheckSig` at consensus
    /// extract.
    #[tokio::test]
    async fn multisig_one_of_one_derives_p2pk_schnorr() {
        let mnemonic = make_local_mnemonics(1).await.into_iter().next().unwrap();
        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let prv_key_data = storage::PrvKeyData::try_new_from_mnemonic(mnemonic, None, EncryptionKind::XChaCha20Poly1305).unwrap();
        let store = wallet.store().as_prv_key_data_store().unwrap();
        store.store(&wallet_secret, prv_key_data.clone()).await.unwrap();
        wallet.inner.store.commit(&wallet_secret).await.unwrap();

        let account = wallet
            .create_account_multisig(&wallet_secret, vec![PrvKeyDataArgs::new(prv_key_data.id, None)], vec![], None, 1)
            .await
            .unwrap();

        let address = account.receive_address().unwrap();
        assert_eq!(
            address.version,
            kaspa_addresses::Version::PubKey,
            "1-of-1 Schnorr multisig must derive a P2PK address; got {:?}",
            address.version
        );
    }

    /// `populate_multisig_redeem_scripts` writes a `bip32_derivations` entry
    /// per PSKT input keyed by the local cosigner's slot pubkey, with a
    /// `KeySource.derivation_path` recording the funded address's actual
    /// cosigner-prefix family path
    /// (`m/45'/111111'/account_index'/<funded_cosigner_index>/<address_type>/<address_index>`).
    /// At sign time the signer reads the recorded path to derive each
    /// cosigner's xprv at the funded family's leaf, regardless of which
    /// family the local wallet itself sits at.
    #[tokio::test]
    async fn multisig_pskt_per_input_derivation_path_attribution() {
        // Operator-Send 2-of-2 (all-local) so the funded family equals the
        // local family at the LOCAL receive address. The attribution path's
        // load-bearing invariant is the structural shape, not which family
        // index lands in the path slot; the cross-family path slot is
        // exercised by the round-trip test below against a peer-family
        // synthetic UTXO.
        let mnemonics = make_local_mnemonics(2).await;
        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let account = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![]).await.unwrap();

        let receive_address = account.receive_address().unwrap();
        let script_public_key = pay_to_address_script(&receive_address);
        let utxo =
            kaspa_consensus_core::tx::UtxoEntry { amount: 100_000_000, script_public_key, block_daa_score: 1, is_coinbase: false };
        let input = InputBuilder::default()
            .utxo_entry(utxo)
            .previous_outpoint(kaspa_consensus_core::tx::TransactionOutpoint {
                transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[0xde; 32]),
                index: 0,
            })
            .sig_op_count(2)
            .build()
            .unwrap();
        let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
        let pskt_inner = pskt_creator.constructor().input(input);
        let mut bundle = Bundle::from(pskt_inner);

        // Pre-condition: PSKT construction leaves bip32_derivations empty.
        assert!(
            bundle.as_ref()[0].inputs[0].bip32_derivations.is_empty(),
            "pre-condition: PSKT-conversion path leaves bip32_derivations empty",
        );

        crate::account::variants::multisig::populate_multisig_redeem_scripts(account.clone(), &mut bundle, 2).await.unwrap();

        let populated = &bundle.as_ref()[0].inputs[0].bip32_derivations;
        assert_eq!(populated.len(), 1, "populate_multisig_redeem_scripts writes exactly one bip32_derivations entry per input");

        let derivation_capable = account.clone().as_derivation_capable().unwrap();
        let local_cosigner_index = derivation_capable.cosigner_index();
        let account_index = derivation_capable.account_index();
        let funded_family_index = derivation_capable.derivation().address_family_index(&receive_address).unwrap();
        assert_eq!(
            funded_family_index.0, local_cosigner_index,
            "operator-Send: funded family index equals local cosigner_index (both = MinimumCosignerIndex)"
        );

        // The entry key is the local cosigner's slot pubkey at the funded
        // family's path; recompute it externally and assert byte-equality.
        let xpub_keys = account.xpub_keys().expect("multisig xpubs").clone();
        let local_xpub = xpub_keys[local_cosigner_index as usize].clone();
        let local_slot_pubkey = *local_xpub
            .derive_child(ChildNumber::new(funded_family_index.0, false).unwrap())
            .unwrap()
            .derive_child(ChildNumber::new(funded_family_index.1.index(), false).unwrap())
            .unwrap()
            .derive_child(ChildNumber::new(funded_family_index.2, false).unwrap())
            .unwrap()
            .public_key();
        let (recorded_pubkey, recorded_key_source) = populated.iter().next().unwrap();
        assert_eq!(*recorded_pubkey, local_slot_pubkey, "bip32_derivations key equals the local cosigner's slot pubkey");

        let key_source = recorded_key_source.as_ref().expect("KeySource attribution is present");
        let expected_fingerprint = local_xpub.fingerprint();
        assert_eq!(key_source.key_fingerprint, expected_fingerprint, "key_fingerprint matches the local xpub fingerprint");

        let expected_path: kaspa_bip32::DerivationPath = format!(
            "m/45'/111111'/{account_index}'/{}/{}/{}",
            funded_family_index.0,
            funded_family_index.1.index(),
            funded_family_index.2
        )
        .parse()
        .unwrap();
        assert_eq!(key_source.derivation_path, expected_path, "derivation_path encodes the funded family's leaf");
    }

    /// Two-of-three cosigner-split round-trip against a peer-cosigner-prefix
    /// family address. The local wallet holds all three seeds (operator-Send
    /// shape) so the test can drive every cosigner's signature in-process,
    /// but funds a *non-local* family's receive[0] (`cosigner_index != local
    /// MinimumCosignerIndex`) to force the cross-family code path. The
    /// signer derives each cosigner's xprv at the per-input
    /// `bip32_derivations.derivation_path` (the funded family's leaf), and
    /// the resulting K-of-N script-sig must extract under
    /// `TxScriptEngine`. Without the family-aware lookup and per-input
    /// derivation, the redeem-script's slot pubkeys would be derived at the
    /// local cosigner_index path and the script would `EvalFalse` at
    /// consensus extract.
    #[tokio::test]
    async fn multisig_pskb_sign_cosigner_split_two_of_three_round_trip() {
        let mnemonics = make_local_mnemonics(3).await;
        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let k: u16 = 2;
        let account = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, k, vec![]).await.unwrap();

        // Pick a peer-family index distinct from the local cosigner_index so
        // the test exercises the cross-family path. With three xpubs sorted
        // lexicographically, the local MinimumCosignerIndex is one of {0,1,2};
        // every other index in [0,3) is a peer family.
        let derivation_capable = account.clone().as_derivation_capable().unwrap();
        let derivation = derivation_capable.derivation();
        let families = derivation.address_manager_families();
        assert_eq!(families.len(), 3, "2-of-3 multisig exposes three cosigner-prefix families");
        let local_cosigner_index = derivation_capable.cosigner_index();
        let peer_family = families.iter().find(|f| f.cosigner_index != local_cosigner_index).expect("at least one peer family");
        let peer_receive_address = peer_family.receive.current_address().unwrap();
        assert_ne!(peer_receive_address, account.receive_address().unwrap(), "peer family's receive address differs from local");

        // Synthetic UTXO at the peer family's receive[0]. The funded-address
        // P2SH script_public_key commits to a redeem-script the post-fix
        // helper builds from the peer family's path.
        let script_public_key = pay_to_address_script(&peer_receive_address);
        let utxo =
            kaspa_consensus_core::tx::UtxoEntry { amount: 100_000_000, script_public_key, block_daa_score: 1, is_coinbase: false };
        let input = InputBuilder::default()
            .utxo_entry(utxo)
            .previous_outpoint(kaspa_consensus_core::tx::TransactionOutpoint {
                transaction_id: kaspa_consensus_core::tx::TransactionId::from_slice(&[0xfe; 32]),
                index: 0,
            })
            .sig_op_count(3)
            .build()
            .unwrap();
        let pskt_creator: PSKT<Creator> = PSKT::default().inputs_modifiable().outputs_modifiable();
        let pskt_inner = pskt_creator.constructor().input(input);
        let mut accumulator = Bundle::from(pskt_inner);

        // Populate redeem_script + bip32_derivations using the peer family's
        // derivation path -- the field the per-cosigner signer below
        // consumes for per-input xprv derivation.
        crate::account::variants::multisig::populate_multisig_redeem_scripts(account.clone(), &mut accumulator, k).await.unwrap();

        // Sign with each local cosigner; the K-cap break-out gate exits
        // after K=2 partial signatures land on the input.
        let multisig: Arc<MultiSig> = account.clone().downcast_arc().expect("account is multisig");
        let prv_key_data_ids = multisig.prv_key_data_ids().as_ref().expect("local cosigner ids").clone();
        let network_id = wallet.network_id().unwrap();
        let prv_key_data_store = wallet.store().as_prv_key_data_store().unwrap();
        let k_usize = k as usize;
        for prv_key_data_id in prv_key_data_ids.iter() {
            let all_full = accumulator.iter().all(|p| p.inputs.iter().all(|i| i.partial_sigs.len() >= k_usize));
            if all_full {
                break;
            }
            let prv_key_data = prv_key_data_store.load_key_data(&wallet_secret, prv_key_data_id).await.unwrap().expect("prv_key_data");
            let per_cosigner_bundle = pskb_signer_for_multisig_cosigner(
                &accumulator,
                account.clone(),
                &prv_key_data,
                None,
                local_cosigner_index,
                network_id,
            )
            .await
            .unwrap();
            for (pskt_idx, signed_pskt_inner) in per_cosigner_bundle.0.into_iter().enumerate() {
                for (input_idx, signed_input) in signed_pskt_inner.inputs.into_iter().enumerate() {
                    let accum_input = std::mem::take(&mut accumulator.0[pskt_idx].inputs[input_idx]);
                    accumulator.0[pskt_idx].inputs[input_idx] = (accum_input + signed_input).unwrap();
                }
            }
        }
        assert_eq!(accumulator.0[0].inputs[0].partial_sigs.len(), k_usize, "exactly K=2 partial signatures landed on the input");

        // Finalize + extract: the extractor runs `TxScriptEngine::execute()`
        // per input against the peer-family redeem-script. Per-cosigner
        // signing keys derived at the local cosigner_index path (the
        // pre-rev-6 behavior) would `EvalFalse` here; the per-input
        // attribution makes the script verify.
        let signer_pskt: PSKT<kaspa_wallet_pskt::pskt::Signer> =
            PSKT::<kaspa_wallet_pskt::pskt::Signer>::from(accumulator.0[0].clone());
        let finalizer_pskt = signer_pskt.finalizer();
        let finalized = finalize_pskt_one_or_more_sig_and_redeem_script(finalizer_pskt).expect("finalize");
        let extractor = finalized.extractor().expect("extractor: finalized PSKT yields an extractor");
        let params = Params::from(network_id);
        let extract_result = extractor.extract_tx(&params);
        assert!(
            extract_result.is_ok(),
            "cosigner-split 2-of-3 cross-family extract_tx must succeed under consensus script verify; got {extract_result:?}",
        );
    }

    /// Three independent wallets sharing the same 2-of-3 multisig xpub set
    /// each expose all three cosigner-prefix families through their
    /// `address_manager_families`. The family-aware lookup
    /// `address_family_index` finds any cosigner's receive address in any
    /// wallet's watch surface, including peer cosigners' family addresses
    /// the wallet does not own a private key for. This is the structural
    /// proof of cross-wallet UTXO visibility: a UTXO funded to Alice's
    /// address is reachable by Bob's wallet and Charlie's wallet even
    /// though only Alice's seed produces a signing key at Alice's family
    /// path.
    #[tokio::test]
    async fn multisig_cross_wallet_utxo_visibility_post_d1_sync() {
        // Three random 24-word mnemonics, one per cosigner. Each is a
        // standalone wallet with that single seed local + the other two
        // mnemonics' xpubs as external. The resulting wallets share the
        // same three-xpub multisig set with distinct local seeds, mirroring
        // a real cosigner-split topology.
        let mnemonics = make_local_mnemonics(3).await;
        let mut external_xpubs_per_cosigner: Vec<Vec<String>> = Vec::with_capacity(3);
        for i in 0..3 {
            let mut peers = Vec::with_capacity(2);
            for (j, peer_mnemonic) in mnemonics.iter().enumerate() {
                if j == i {
                    continue;
                }
                peers.push(external_xpub_for_testnet(peer_mnemonic.phrase()).await);
            }
            external_xpubs_per_cosigner.push(peers);
        }

        let mut wallets_and_accounts: Vec<(Arc<Wallet>, Arc<dyn Account>)> = Vec::with_capacity(3);
        for i in 0..3 {
            let wallet = test_wallet().await;
            let wallet_secret = Secret::new(vec![]);
            let prv_key_data =
                storage::PrvKeyData::try_new_from_mnemonic(mnemonics[i].clone(), None, EncryptionKind::XChaCha20Poly1305).unwrap();
            let store = wallet.store().as_prv_key_data_store().unwrap();
            store.store(&wallet_secret, prv_key_data.clone()).await.unwrap();
            wallet.inner.store.commit(&wallet_secret).await.unwrap();
            let create_args = vec![PrvKeyDataArgs::new(prv_key_data.id, None)];
            let account = wallet
                .create_account_multisig(&wallet_secret, create_args, external_xpubs_per_cosigner[i].clone(), None, 2)
                .await
                .unwrap();
            wallets_and_accounts.push((wallet, account));
        }

        // Each `AddressManager` lazily populates its `address_to_index_map`
        // on first address production. Trigger generation across every
        // cosigner-prefix family per wallet so the family-aware lookup has
        // a populated index map for peer families, matching what the
        // production sync layer drives off the UTXO-watch stream.
        for (_, account) in wallets_and_accounts.iter() {
            let derivation = account.clone().as_derivation_capable().unwrap().derivation();
            for family in derivation.address_manager_families() {
                let _ = family.receive.current_address().unwrap();
            }
        }

        // Cross-binding invariant: the three wallets share the same sorted
        // xpub set; the per-wallet receive addresses correspond to each
        // wallet's MinimumCosignerIndex family. Collect every wallet's
        // own family receive address, then assert every other wallet finds
        // it through `address_family_index`.
        let mut own_family_addresses: Vec<(Address, u32)> = Vec::with_capacity(3);
        for (_, account) in wallets_and_accounts.iter() {
            let derivation_capable = account.clone().as_derivation_capable().unwrap();
            let local_idx = derivation_capable.cosigner_index();
            let receive = account.receive_address().unwrap();
            own_family_addresses.push((receive, local_idx));
        }

        // The local cosigner_index values must form a permutation of [0,3)
        // (each wallet's MinimumCosignerIndex equals its own xpub's
        // sorted-position; distinct seeds map to distinct positions).
        let mut sorted_local_indices: Vec<u32> = own_family_addresses.iter().map(|(_, idx)| *idx).collect();
        sorted_local_indices.sort_unstable();
        assert_eq!(sorted_local_indices, vec![0, 1, 2], "three cosigners occupy distinct sorted positions [0,3)");

        for (peer_idx, (address, expected_cosigner_index)) in own_family_addresses.iter().enumerate() {
            for (visitor_idx, (_, account)) in wallets_and_accounts.iter().enumerate() {
                let derivation = account.clone().as_derivation_capable().unwrap().derivation();
                let result = derivation
                    .address_family_index(address)
                    .unwrap_or_else(|_| panic!("wallet {visitor_idx} missing family-aware visibility on wallet {peer_idx}'s address"));
                assert_eq!(
                    result.0, *expected_cosigner_index,
                    "wallet {visitor_idx} sees wallet {peer_idx}'s address at the expected cosigner_index family",
                );
            }
        }
    }

    /// Operator-Send byte-identity gate. A multisig account whose local
    /// cosigner set is all of the N seeds (no externals) places
    /// `MinimumCosignerIndex` at the smallest sorted position of the local
    /// xpubs, which is also 0 for the all-local set. The post-fix derivation
    /// path applies that same index step to every cosigner's xpub when
    /// assembling the redeem-script, producing the same P2SH address
    /// pre-fix and post-fix. Pins the derivation-rule NO-CHANGE invariant on the
    /// derivation rule against the pre-fix HEAD `ad08e0d6` reference
    /// captured offline via cycle-1 derivation walk.
    #[tokio::test]
    async fn multisig_operator_send_byte_identical_pre_post_fix() {
        // Deterministic 24-word phrases reproducible across runs.
        let phrase_a = "caution guide valley easily latin already visual fancy fork car switch runway \
                        vicious polar surprise fence boil light nut invite fiction visa hamster coyote";
        let phrase_b = "fiber boy desk trip pitch snake table awkward endorse car learn forest \
                        solid ticket enemy pink gesture wealth iron chaos clock gather honey farm";
        let mnemonics = [Mnemonic::new(phrase_a, Language::English).unwrap(), Mnemonic::new(phrase_b, Language::English).unwrap()];
        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let mnemonics_with_secrets: Vec<(Mnemonic, Option<Secret>)> = mnemonics.iter().cloned().map(|m| (m, None)).collect();
        let account = wallet.import_multisig_with_mnemonic(&wallet_secret, mnemonics_with_secrets, 2, vec![]).await.unwrap();

        // Operator-Send invariant: with all seeds local the smallest
        // sorted-position across local xpubs equals 0.
        let derivation_capable = account.clone().as_derivation_capable().unwrap();
        let local_cosigner_index = derivation_capable.cosigner_index();
        assert_eq!(local_cosigner_index, 0, "operator-Send (all seeds local) sets MinimumCosignerIndex to 0 by construction");

        // Independently rebuild the receive[0] script_public_key from the
        // canonical xpub-walk using the post-fix derivation rule
        // (`derive_child(0).derive_child(receive=0).derive_child(0)` on
        // each cosigner xpub). The post-fix rule is byte-identical to the
        // pre-fix rule (NO CHANGE at the derivation layer); any divergence would surface
        // here as an address mismatch against the canonical externally-built
        // P2SH script.
        let xpub_keys = account.xpub_keys().expect("multisig xpubs").clone();
        let mut slot_pubkeys: Vec<secp256k1::PublicKey> = Vec::with_capacity(xpub_keys.len());
        for xpub in xpub_keys.iter() {
            let derived = xpub
                .clone()
                .derive_child(ChildNumber::new(0, false).unwrap())
                .unwrap()
                .derive_child(ChildNumber::new(0, false).unwrap())
                .unwrap()
                .derive_child(ChildNumber::new(0, false).unwrap())
                .unwrap();
            slot_pubkeys.push(*derived.public_key());
        }
        let redeem_script = multisig_redeem_script(slot_pubkeys.iter().map(|pk| pk.x_only_public_key().0.serialize()), 2).unwrap();
        let expected_script = pay_to_script_hash_script(redeem_script.as_slice());

        let receive_address = account.receive_address().unwrap();
        let actual_script = pay_to_address_script(&receive_address);
        assert_eq!(
            expected_script, actual_script,
            "operator-Send receive[0] script_public_key must match the canonical xpub-walk's P2SH commitment byte-for-byte",
        );
    }

    /// A 1-of-1 multisig account with `ecdsa=true` derives a P2PK-ECDSA
    /// receive address. `create_account_multisig` hardcodes `ecdsa=false`, so
    /// the ECDSA-variant account is built via `MultiSig::try_new` directly.
    /// Verifies that the single-cosigner P2PK branch in
    /// `derivation::create_address` propagates the `ecdsa` flag to
    /// `PubkeyDerivationManager::create_address`, producing the
    /// `Version::PubKeyECDSA` address shape Go-wallet derives for an ECDSA
    /// 1-of-1 keypair wallet.
    #[tokio::test]
    async fn multisig_one_of_one_derives_p2pk_ecdsa() {
        let mnemonic = make_local_mnemonics(1).await.into_iter().next().unwrap();
        let wallet = test_wallet().await;
        let wallet_secret = Secret::new(vec![]);
        let prv_key_data = storage::PrvKeyData::try_new_from_mnemonic(mnemonic, None, EncryptionKind::XChaCha20Poly1305).unwrap();
        let store = wallet.store().as_prv_key_data_store().unwrap();
        store.store(&wallet_secret, prv_key_data.clone()).await.unwrap();
        wallet.inner.store.commit(&wallet_secret).await.unwrap();

        let xpub_key = prv_key_data.create_xpub(None, MULTISIG_ACCOUNT_KIND.into(), 0).await.unwrap();

        let account =
            MultiSig::try_new(&wallet, None, Arc::new(vec![xpub_key]), Some(Arc::new(vec![prv_key_data.id])), Some(0), 1, true)
                .await
                .unwrap();

        let address = account.receive_address().unwrap();
        assert_eq!(
            address.version,
            kaspa_addresses::Version::PubKeyECDSA,
            "1-of-1 ECDSA multisig must derive a P2PK-ECDSA address; got {:?}",
            address.version
        );
    }
}
