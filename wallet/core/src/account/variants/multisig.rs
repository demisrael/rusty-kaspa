//!
//! MultiSig account implementation.
//!

use crate::account::Inner;
use crate::account::pskb::{PSKBSigner, PSKTGenerator, bundle_from_pskt_generator, pskb_signer_for_multisig_cosigner};
use crate::account::{Fees, GenerationNotifier, PaymentDestination};
use crate::derivation::{AddressDerivationManager, AddressDerivationManagerTrait};
use crate::imports::*;
use crate::tx::{Generator, GeneratorSettings, GeneratorSummary, Signer};
use kaspa_bip32::{ChildNumber, DerivationPath, Prefix as KeyPrefix};
use kaspa_txscript::{extract_script_pub_key_address, multisig_redeem_script};
use kaspa_wallet_pskt::bundle::Bundle;
use kaspa_wallet_pskt::prelude::KeySource;

pub const MULTISIG_ACCOUNT_KIND: &str = "kaspa-multisig-standard";

pub struct Ctor {}

#[async_trait]
impl Factory for Ctor {
    fn name(&self) -> String {
        "multisig".to_string()
    }

    fn description(&self) -> String {
        "Kaspa Core Multi-Signature Account".to_string()
    }

    async fn try_load(
        &self,
        wallet: &Arc<Wallet>,
        storage: &AccountStorage,
        meta: Option<Arc<AccountMetadata>>,
    ) -> Result<Arc<dyn Account>> {
        Ok(Arc::new(MultiSig::try_load(wallet, storage, meta).await?))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct Payload {
    pub xpub_keys: ExtendedPublicKeys,
    pub cosigner_index: Option<u8>,
    pub minimum_signatures: u16,
    pub ecdsa: bool,
    pub account_index: u64,
}

impl Payload {
    pub fn new(
        xpub_keys: ExtendedPublicKeys,
        cosigner_index: Option<u8>,
        minimum_signatures: u16,
        ecdsa: bool,
        account_index: u64,
    ) -> Self {
        Self { xpub_keys, cosigner_index, minimum_signatures, ecdsa, account_index }
    }

    pub fn try_load(storage: &AccountStorage) -> Result<Self> {
        Ok(Self::try_from_slice(storage.serialized.as_slice())?)
    }
}

impl Storable for Payload {
    const STORAGE_MAGIC: u32 = 0x4749534d;
    const STORAGE_VERSION: u32 = 0;
}

impl AccountStorable for Payload {}

impl BorshSerialize for Payload {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        StorageHeader::new(Self::STORAGE_MAGIC, Self::STORAGE_VERSION).serialize(writer)?;

        BorshSerialize::serialize(&self.xpub_keys, writer)?;
        BorshSerialize::serialize(&self.cosigner_index, writer)?;
        BorshSerialize::serialize(&self.minimum_signatures, writer)?;
        BorshSerialize::serialize(&self.ecdsa, writer)?;
        BorshSerialize::serialize(&self.account_index, writer)?;

        Ok(())
    }
}

impl BorshDeserialize for Payload {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> IoResult<Self> {
        let StorageHeader { version: _, .. } =
            StorageHeader::deserialize_reader(reader)?.try_magic(Self::STORAGE_MAGIC)?.try_version(Self::STORAGE_VERSION)?;

        let xpub_keys = BorshDeserialize::deserialize_reader(reader)?;
        let cosigner_index = BorshDeserialize::deserialize_reader(reader)?;
        let minimum_signatures = BorshDeserialize::deserialize_reader(reader)?;
        let ecdsa = BorshDeserialize::deserialize_reader(reader)?;
        // Trailing `account_index` is an additive suffix on STORAGE_VERSION 0.
        // Older payloads (written before the field existed) end after
        // `ecdsa`; a clean EOF at this position (zero further bytes
        // available) signals that the loaded wallet predates the field,
        // in which case the implicit default `0` preserves the
        // single-multisig-account-per-wallet derivation at
        // `m/45'/111111'/0'`. A partial read (between 1 and 7 trailing
        // bytes) is treated as corruption and propagates the underlying
        // read error, so a truncated wallet file is not silently accepted
        // as `account_index = 0`.
        let mut tail = [0u8; 8];
        let account_index = match reader.read(&mut tail[..1])? {
            0 => 0,
            _ => {
                reader.read_exact(&mut tail[1..])?;
                u64::from_le_bytes(tail)
            }
        };

        Ok(Self { xpub_keys, cosigner_index, minimum_signatures, ecdsa, account_index })
    }
}

pub struct MultiSig {
    inner: Arc<Inner>,
    xpub_keys: ExtendedPublicKeys,
    prv_key_data_ids: Option<Arc<Vec<PrvKeyDataId>>>,
    cosigner_index: Option<u8>,
    minimum_signatures: u16,
    ecdsa: bool,
    account_index: u64,
    derivation: Arc<AddressDerivationManager>,
}

impl MultiSig {
    pub async fn try_new(
        wallet: &Arc<Wallet>,
        name: Option<String>,
        xpub_keys: ExtendedPublicKeys,
        prv_key_data_ids: Option<Arc<Vec<PrvKeyDataId>>>,
        cosigner_index: Option<u8>,
        minimum_signatures: u16,
        ecdsa: bool,
        account_index: u64,
    ) -> Result<Self> {
        let storable = Payload::new(xpub_keys.clone(), cosigner_index, minimum_signatures, ecdsa, account_index);
        let settings = AccountSettings { name, ..Default::default() };
        let (id, storage_key) = make_account_hashes(from_multisig(&prv_key_data_ids, &storable));
        let inner = Arc::new(Inner::new(wallet, id, storage_key, settings));

        let derivation = AddressDerivationManager::new(
            wallet,
            MULTISIG_ACCOUNT_KIND.into(),
            &xpub_keys,
            ecdsa,
            account_index,
            cosigner_index.map(|v| v as u32),
            minimum_signatures,
            Default::default(),
        )
        .await?;

        Ok(Self { inner, xpub_keys, cosigner_index, minimum_signatures, ecdsa, account_index, derivation, prv_key_data_ids })
    }

    pub async fn try_load(wallet: &Arc<Wallet>, storage: &AccountStorage, meta: Option<Arc<AccountMetadata>>) -> Result<Self> {
        let storable = Payload::try_load(storage)?;
        let inner = Arc::new(Inner::from_storage(wallet, storage));

        let Payload { xpub_keys, cosigner_index, minimum_signatures, ecdsa, account_index, .. } = storable;

        let address_derivation_indexes = meta.and_then(|meta| meta.address_derivation_indexes()).unwrap_or_default();

        let derivation = AddressDerivationManager::new(
            wallet,
            MULTISIG_ACCOUNT_KIND.into(),
            &xpub_keys,
            ecdsa,
            account_index,
            cosigner_index.map(|v| v as u32),
            minimum_signatures,
            address_derivation_indexes,
        )
        .await?;

        // TODO @maxim check variants transforms - None->Ok(None), Multiple->Ok(Some()), Single->Err()
        let prv_key_data_ids = storage.prv_key_data_ids.clone().try_into()?;

        Ok(Self { inner, xpub_keys, cosigner_index, minimum_signatures, ecdsa, account_index, derivation, prv_key_data_ids })
    }

    pub fn prv_key_data_ids(&self) -> &Option<Arc<Vec<PrvKeyDataId>>> {
        &self.prv_key_data_ids
    }

    pub fn minimum_signatures(&self) -> u16 {
        self.minimum_signatures
    }

    fn watch_only(&self) -> bool {
        self.prv_key_data_ids.is_none()
    }

    /// Whether send/sweep/pskb_from_send_generator should route through the
    /// single-signature signing path (P2PK) rather than the K-of-N multisig
    /// signing path (P2SH-multisig).
    ///
    /// A single-cosigner multisig account derives a P2PK receive/change
    /// address: see `create_address`, where `keys.len() <= 1` returns a P2PK
    /// address rather than a P2SH-multisig address. Spending such an address
    /// requires a single-sig `script_sig` (one signature push, no
    /// redeem-script push); finalizing it through the K-of-N path emits a
    /// P2SH-multisig `script_sig` shape and fails `OpCheckSig` at consensus
    /// extract. Watch-only accounts (no local cosigner material) cannot
    /// produce signatures via either path and are excluded here so the K-of-N
    /// path's existing `MultisigInsufficientCosignerMaterial` error surfaces
    /// to the caller.
    ///
    /// A 1-of-1 multisig resolves to a P2PK address, and finalization keys
    /// off the per-input signature-pair count: a multi-pair input builds a
    /// P2SH-multisig `sigScript`, a single-pair input builds a P2PK
    /// `sigScript`.
    fn route_as_single_sig(&self) -> bool {
        // Single xpub (P2PK address shape per `derivation::create_address`)
        // AND exactly one local cosigner key-data id, which is the operator's
        // seed and the only signer needed for the P2PK spend. Watch-only
        // (`None`) and any malformed multi-id-with-single-xpub construction
        // fall through to the K-of-N branch, whose error path remains the
        // single observable for missing cosigner material.
        self.xpub_keys.len() == 1 && self.prv_key_data_ids.as_ref().map(|ids| ids.len()) == Some(1)
    }

    /// Load the single local cosigner's key data for the P2PK send routing
    /// branch. Precondition: `route_as_single_sig` returned `true`, which
    /// guarantees `prv_key_data_ids` is `Some(_)` with exactly one entry.
    async fn load_sole_cosigner_keydata(&self, wallet_secret: &Secret) -> Result<PrvKeyData> {
        let id = self.prv_key_data_ids.as_ref().expect("route_as_single_sig guarantees Some(_)")[0];
        self.inner.store().as_prv_key_data_store()?.load_key_data(wallet_secret, &id).await?.ok_or(Error::PrivateKeyNotFound(id))
    }
}

#[async_trait]
impl Account for MultiSig {
    fn inner(&self) -> &Arc<Inner> {
        &self.inner
    }

    fn account_kind(&self) -> AccountKind {
        MULTISIG_ACCOUNT_KIND.into()
    }

    fn feature(&self) -> Option<String> {
        match self.watch_only() {
            true => Some("multisig-watch".to_string()),
            false => None,
        }
    }

    fn xpub_keys(&self) -> Option<&ExtendedPublicKeys> {
        Some(&self.xpub_keys)
    }

    fn prv_key_data_id(&self) -> Result<&PrvKeyDataId> {
        Err(Error::AccountKindFeature)
    }

    fn as_dyn_arc(self: Arc<Self>) -> Arc<dyn Account> {
        self
    }

    fn sig_op_count(&self) -> u8 {
        u8::try_from(self.xpub_keys.len()).unwrap()
    }

    fn minimum_signatures(&self) -> u16 {
        self.minimum_signatures
    }

    fn receive_address(&self) -> Result<Address> {
        self.derivation.receive_address_manager().current_address()
    }

    fn change_address(&self) -> Result<Address> {
        self.derivation.change_address_manager().current_address()
    }

    fn to_storage(&self) -> Result<AccountStorage> {
        let settings = self.context().settings.clone();
        let storable =
            Payload::new(self.xpub_keys.clone(), self.cosigner_index, self.minimum_signatures, self.ecdsa, self.account_index);
        let account_storage = AccountStorage::try_new(
            MULTISIG_ACCOUNT_KIND.into(),
            self.id(),
            self.storage_key(),
            self.prv_key_data_ids.clone().try_into()?,
            settings,
            storable,
        )?;

        Ok(account_storage)
    }

    fn metadata(&self) -> Result<Option<AccountMetadata>> {
        let metadata = AccountMetadata::new(self.inner.id, self.derivation.address_derivation_meta());
        Ok(Some(metadata))
    }

    fn descriptor(&self) -> Result<AccountDescriptor> {
        let descriptor = AccountDescriptor::new(
            MULTISIG_ACCOUNT_KIND.into(),
            *self.id(),
            self.name(),
            self.balance(),
            self.prv_key_data_ids.clone().try_into()?,
            self.receive_address().ok(),
            self.change_address().ok(),
            None,
        )
        .with_property(AccountDescriptorProperty::XpubKeys, self.xpub_keys.clone().into())
        .with_property(AccountDescriptorProperty::Ecdsa, self.ecdsa.into())
        .with_property(AccountDescriptorProperty::DerivationMeta, self.derivation.address_derivation_meta().into());

        Ok(descriptor)
    }

    fn as_derivation_capable(self: Arc<Self>) -> Result<Arc<dyn DerivationCapableAccount>> {
        Ok(self.clone())
    }

    fn get_list_string(&self) -> Result<String> {
        let name = style(self.name_with_id()).blue();
        let balance = self.balance_as_strings(None)?;
        let mature_utxo_size = self.utxo_context().mature_utxo_size();
        let pending_utxo_size = self.utxo_context().pending_utxo_size();
        let index_suffix = format!("[account_index={}]", self.account_index);
        let info = match (mature_utxo_size, pending_utxo_size) {
            (0, 0) => index_suffix,
            (_, 0) => format!("{} UTXOs {}", mature_utxo_size.separated_string(), index_suffix),
            (0, _) => format!("{} UTXOs pending {}", pending_utxo_size.separated_string(), index_suffix),
            _ => format!(
                "{} UTXOs, {} UTXOs pending {}",
                mature_utxo_size.separated_string(),
                pending_utxo_size.separated_string(),
                index_suffix
            ),
        };
        Ok(format!("{name}: {balance}   {}", style(info).dim()))
    }

    /// Build, sign, and submit transactions spending this multisig account.
    ///
    /// Routing decision: `route_as_single_sig` (single xpub + single local
    /// cosigner id) takes the P2PK `Signer` path -- one signature push, no
    /// redeem-script push. Every other shape, including watch-only and any
    /// malformed single-xpub-with-multi-id construction, falls through to the
    /// K-of-N PSKB path which assembles `build_multisig_signed_bundle` from
    /// the local cosigner key-data ids and broadcasts via `pskb_broadcast`;
    /// `MultisigInsufficientCosignerMaterial` surfaces when `prv_key_data_ids`
    /// is absent. See `route_as_single_sig` for the P2PK branch rationale.
    async fn send(
        self: Arc<Self>,
        destination: PaymentDestination,
        fee_rate: Option<f64>,
        priority_fee_sompi: Fees,
        payload: Option<Vec<u8>>,
        wallet_secret: Secret,
        payment_secret: Option<Secret>,
        abortable: &Abortable,
        notifier: Option<GenerationNotifier>,
    ) -> Result<(GeneratorSummary, Vec<kaspa_hashes::Hash>)> {
        if self.route_as_single_sig() {
            let keydata = self.load_sole_cosigner_keydata(&wallet_secret).await?;
            let signer = Arc::new(Signer::new(self.clone().as_dyn_arc(), keydata, payment_secret));
            let settings = GeneratorSettings::try_new_with_account(
                self.clone().as_dyn_arc(),
                destination,
                fee_rate,
                priority_fee_sompi,
                payload,
            )?;
            let generator = Generator::try_new(settings, Some(signer), Some(abortable))?;

            let mut stream = generator.stream();
            let mut ids = vec![];
            while let Some(transaction) = stream.try_next().await? {
                transaction.try_sign()?;
                ids.push(transaction.try_submit(&self.wallet().rpc_api()).await?);

                if let Some(notifier) = notifier.as_ref() {
                    notifier(&transaction);
                }
                yield_executor().await;
            }

            return Ok((generator.summary(), ids));
        }

        let xpub_keys_strings: Vec<String> = self.xpub_keys.iter().map(|k| k.to_string(Some(KeyPrefix::XPUB))).collect();
        let prv_key_data_ids: Vec<PrvKeyDataId> = self
            .prv_key_data_ids
            .as_ref()
            .ok_or(Error::MultisigInsufficientCosignerMaterial { local: 0, required: self.minimum_signatures })?
            .as_ref()
            .clone();
        // Broadcast path: a partial bundle is rejected at consensus
        // `OpCheckMultiSig` extract. Reject `L < K` at the wallet layer so
        // the operator sees the same `MultisigInsufficientCosignerMaterial`
        // diagnostic the K-of-N PSKB exchange flow would have produced. The
        // cosigner-split topology (`L = 1, K >= 2`) routes through
        // `pskb_from_send_generator` instead, which returns a partial
        // bundle for downstream `pskb_sign` rounds before broadcast.
        if prv_key_data_ids.len() < self.minimum_signatures as usize {
            return Err(Error::MultisigInsufficientCosignerMaterial {
                local: prv_key_data_ids.len(),
                required: self.minimum_signatures,
            });
        }
        let settings =
            GeneratorSettings::try_new_with_account(self.clone().as_dyn_arc(), destination, fee_rate, priority_fee_sompi, payload)?;

        let (bundle, summary) = build_multisig_signed_bundle(
            self.clone().as_dyn_arc(),
            xpub_keys_strings,
            prv_key_data_ids,
            self.minimum_signatures,
            settings,
            wallet_secret,
            payment_secret,
            abortable,
            notifier,
        )
        .await?;

        let ids = self.clone().as_dyn_arc().pskb_broadcast(&bundle).await?;
        Ok((summary, ids))
    }

    /// Drain every spendable UTXO to a fresh change address and broadcast.
    ///
    /// Same routing decision as `send`: `route_as_single_sig` -> P2PK `Signer`
    /// path; everything else falls through to the K-of-N PSKB path via
    /// `build_multisig_signed_bundle` + `pskb_broadcast`, with
    /// `MultisigInsufficientCosignerMaterial` surfacing when local cosigner
    /// material is absent. See `route_as_single_sig` for the P2PK branch
    /// rationale.
    async fn sweep(
        self: Arc<Self>,
        wallet_secret: Secret,
        payment_secret: Option<Secret>,
        fee_rate: Option<f64>,
        abortable: &Abortable,
        notifier: Option<GenerationNotifier>,
    ) -> Result<(GeneratorSummary, Vec<kaspa_hashes::Hash>)> {
        if self.route_as_single_sig() {
            let keydata = self.load_sole_cosigner_keydata(&wallet_secret).await?;
            let signer = Arc::new(Signer::new(self.clone().as_dyn_arc(), keydata, payment_secret));
            let settings = GeneratorSettings::try_new_with_account(
                self.clone().as_dyn_arc(),
                PaymentDestination::Change,
                fee_rate,
                Fees::None,
                None,
            )?;
            let generator = Generator::try_new(settings, Some(signer), Some(abortable))?;

            let mut stream = generator.stream();
            let mut ids = vec![];
            while let Some(transaction) = stream.try_next().await? {
                transaction.try_sign()?;
                ids.push(transaction.try_submit(&self.wallet().rpc_api()).await?);

                if let Some(notifier) = notifier.as_ref() {
                    notifier(&transaction);
                }
                yield_executor().await;
            }

            return Ok((generator.summary(), ids));
        }

        let xpub_keys_strings: Vec<String> = self.xpub_keys.iter().map(|k| k.to_string(Some(KeyPrefix::XPUB))).collect();
        let prv_key_data_ids: Vec<PrvKeyDataId> = self
            .prv_key_data_ids
            .as_ref()
            .ok_or(Error::MultisigInsufficientCosignerMaterial { local: 0, required: self.minimum_signatures })?
            .as_ref()
            .clone();
        // Broadcast path: same L < K reject as `send`. A cosigner-split
        // wallet sweeping its UTXOs cannot produce a K-quorum on its own
        // and must route through `pskb_from_send_generator` + downstream
        // `pskb_sign` exchange instead.
        if prv_key_data_ids.len() < self.minimum_signatures as usize {
            return Err(Error::MultisigInsufficientCosignerMaterial {
                local: prv_key_data_ids.len(),
                required: self.minimum_signatures,
            });
        }
        let settings = GeneratorSettings::try_new_with_account(
            self.clone().as_dyn_arc(),
            PaymentDestination::Change,
            fee_rate,
            Fees::None,
            None,
        )?;

        let (bundle, summary) = build_multisig_signed_bundle(
            self.clone().as_dyn_arc(),
            xpub_keys_strings,
            prv_key_data_ids,
            self.minimum_signatures,
            settings,
            wallet_secret,
            payment_secret,
            abortable,
            notifier,
        )
        .await?;

        let ids = self.clone().as_dyn_arc().pskb_broadcast(&bundle).await?;
        Ok((summary, ids))
    }

    /// Build a signed PSKT bundle for the spend without broadcasting.
    ///
    /// Same routing decision as `send`: `route_as_single_sig` -> P2PK path,
    /// driven through `PSKBSigner` + `PSKTGenerator` rather than the
    /// stream-and-submit `Signer` shape used by `send`/`sweep`. The K-of-N
    /// fall-through reuses `build_multisig_signed_bundle` and returns the
    /// bundle directly, leaving broadcast to the caller. See
    /// `route_as_single_sig` for the P2PK branch rationale.
    async fn pskb_from_send_generator(
        self: Arc<Self>,
        destination: PaymentDestination,
        fee_rate: Option<f64>,
        priority_fee_sompi: Fees,
        payload: Option<Vec<u8>>,
        wallet_secret: Secret,
        payment_secret: Option<Secret>,
        abortable: &Abortable,
    ) -> Result<Bundle, Error> {
        if self.route_as_single_sig() {
            let keydata = self.load_sole_cosigner_keydata(&wallet_secret).await?;
            let signer = Arc::new(PSKBSigner::new(self.clone().as_dyn_arc(), keydata, payment_secret));
            let settings = GeneratorSettings::try_new_with_account(
                self.clone().as_dyn_arc(),
                destination,
                fee_rate,
                priority_fee_sompi,
                payload,
            )?;
            let generator = Generator::try_new(settings, None, Some(abortable))?;
            let pskt_generator = PSKTGenerator::new(generator, signer, self.wallet().address_prefix()?);
            return bundle_from_pskt_generator(pskt_generator).await;
        }

        let xpub_keys_strings: Vec<String> = self.xpub_keys.iter().map(|k| k.to_string(Some(KeyPrefix::XPUB))).collect();
        let prv_key_data_ids: Vec<PrvKeyDataId> = self
            .prv_key_data_ids
            .as_ref()
            .ok_or(Error::MultisigInsufficientCosignerMaterial { local: 0, required: self.minimum_signatures })?
            .as_ref()
            .clone();
        let settings =
            GeneratorSettings::try_new_with_account(self.clone().as_dyn_arc(), destination, fee_rate, priority_fee_sompi, payload)?;

        let (bundle, _summary) = build_multisig_signed_bundle(
            self.clone().as_dyn_arc(),
            xpub_keys_strings,
            prv_key_data_ids,
            self.minimum_signatures,
            settings,
            wallet_secret,
            payment_secret,
            abortable,
            None,
        )
        .await?;
        Ok(bundle)
    }

    /// Apply local-cosigner signatures to an inbound PSKT bundle.
    ///
    /// Two divergences from the trait-default single-signature path are
    /// required to make multisig spending actually work:
    ///
    /// 1. **`input.redeem_script` MUST be populated on every PSKT input
    ///    before the per-cosigner signer is invoked.** The PSKT-conversion
    ///    helper builds inputs with `redeem_script: None`; without it the
    ///    Finalizer's `None` branch emits an empty `script_sig` and the
    ///    consensus-side P2SH script-hash check rejects the extracted
    ///    transaction. The shared helper applies the population step
    ///    idempotently (an upstream cosigner's contribution is preserved).
    /// 2. **Per-cosigner key derivation uses the multisig path**
    ///    `m/45'/111111'/account_index'/<cosigner_index>/<address_type>/<address_index>`,
    ///    not the BIP-32 single-sig path. Routing through
    ///    `pskb_signer_for_multisig_cosigner` enforces this; the
    ///    trait-default path routes through `pskb_signer_for_address` whose
    ///    derivation is single-sig and produces signing keys whose pubkeys
    ///    do not match any redeem-script slot.
    ///
    /// The override loops the local cosigner set: each iteration loads
    /// the corresponding private key data, signs every PSKT input whose
    /// redeem-script slot the cosigner can satisfy, and merges the
    /// per-cosigner partial signatures into the accumulator. The per-input
    /// `K`-cap break-out gate caps the bundle at exactly K signatures so
    /// the resulting `script_sig` does not trip `CleanStack` at consensus.
    async fn pskb_sign(
        self: Arc<Self>,
        bundle: &Bundle,
        wallet_secret: Secret,
        payment_secret: Option<Secret>,
        _sign_for_address: Option<&Address>,
    ) -> Result<Bundle, Error> {
        let prv_key_data_ids: Vec<PrvKeyDataId> = match self.prv_key_data_ids.as_ref() {
            Some(ids) if !ids.is_empty() => ids.as_ref().clone(),
            _ => return Err(Error::MultisigInsufficientCosignerMaterial { local: 0, required: self.minimum_signatures }),
        };

        let k = self.minimum_signatures;
        let network_id = self.wallet().clone().network_id()?;
        let prv_key_data_store = self.wallet().store().as_prv_key_data_store()?;
        let multisig_derivation_index = self.cosigner_index();

        let account_dyn = self.clone().as_dyn_arc();
        let mut accumulator = Bundle(bundle.0.clone());
        populate_multisig_redeem_scripts(account_dyn.clone(), &mut accumulator, k).await?;

        for prv_key_data_id in prv_key_data_ids.iter() {
            let already_fully_signed =
                accumulator.iter().all(|pskt_inner| pskt_inner.inputs.iter().all(|input| input.partial_sigs.len() >= k as usize));
            if already_fully_signed {
                break;
            }

            let prv_key_data = prv_key_data_store
                .load_key_data(&wallet_secret, prv_key_data_id)
                .await?
                .ok_or(Error::PrivateKeyNotFound(*prv_key_data_id))?;

            let per_cosigner_bundle = pskb_signer_for_multisig_cosigner(
                &accumulator,
                account_dyn.clone(),
                &prv_key_data,
                payment_secret.as_ref(),
                multisig_derivation_index,
                network_id,
            )
            .await?;

            if accumulator.0.len() != per_cosigner_bundle.0.len() {
                return Err(Error::custom("multisig signed bundle PSKT count mismatch with accumulator"));
            }
            for (pskt_idx, signed_pskt_inner) in per_cosigner_bundle.0.into_iter().enumerate() {
                if accumulator.0[pskt_idx].inputs.len() != signed_pskt_inner.inputs.len() {
                    return Err(Error::custom("multisig signed bundle PSKT input count mismatch with accumulator"));
                }
                for (input_idx, signed_input) in signed_pskt_inner.inputs.into_iter().enumerate() {
                    let accum_input = std::mem::take(&mut accumulator.0[pskt_idx].inputs[input_idx]);
                    accumulator.0[pskt_idx].inputs[input_idx] =
                        (accum_input + signed_input).map_err(|e| Error::custom(e.to_string()))?;
                }
            }
        }

        Ok(accumulator)
    }
}

/// Build a PSKB across the operator's local cosigner set.
///
/// Algorithm: build the empty PSKT bundle once via the standard PSKBSigner
/// machinery (the placeholder signer is held but never invoked during stream
/// polling), then iterate over the local cosigner key-data IDs. Each
/// iteration's per-cosigner signature accumulates via `Input::add`
/// (per-input `partial_sigs` merge with previous-outpoint validation). A
/// per-input K-cap break-out gate caps the bundle at exactly K signatures
/// per input; `OpCheckMultiSig` pops K, and any L-K leftover signatures
/// trip the `CleanStack` consensus check.
///
/// The bundle returned has `min(L, K)` partial signatures per input where
/// `L = prv_key_data_ids.len()`. A wallet holding all K cosigner seeds
/// locally (operator-Send topology) produces a fully-signed bundle ready
/// for broadcast. A wallet holding `1 <= L < K` seeds (cosigner-split
/// topology) produces a partial bundle that must complete the K-quorum
/// through downstream `pskb_sign` rounds before broadcast. Callers that
/// directly broadcast the returned bundle (e.g., `MultiSig::send` /
/// `MultiSig::sweep`) MUST reject `L < K` themselves before invoking this
/// helper, since a partial bundle is rejected at the consensus
/// `OpCheckMultiSig` extract.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_multisig_signed_bundle(
    account: Arc<dyn Account>,
    xpub_keys_strings: Vec<String>,
    prv_key_data_ids: Vec<PrvKeyDataId>,
    minimum_signatures: u16,
    settings: GeneratorSettings,
    wallet_secret: Secret,
    payment_secret: Option<Secret>,
    abortable: &Abortable,
    _notifier: Option<GenerationNotifier>,
) -> Result<(Bundle, GeneratorSummary)> {
    let k = minimum_signatures;
    let l = prv_key_data_ids.len();
    if prv_key_data_ids.is_empty() {
        return Err(Error::MultisigInsufficientCosignerMaterial { local: l, required: k });
    }

    let network_id = account.wallet().clone().network_id()?;
    let prv_key_data_store = account.wallet().store().as_prv_key_data_store()?;

    // The local wallet's cosigner_index. Threaded through to
    // `pskb_signer_for_multisig_cosigner` as the `default_cosigner_index`
    // fallback for inputs whose `bip32_derivations` is empty (a synthetic
    // primitive test fixture, for example). The primary signing path
    // consumes the per-input `KeySource.derivation_path` populated by
    // `populate_multisig_redeem_scripts` below, which encodes the funded
    // cosigner-prefix family's leaf path -- the same path each cosigner
    // derives its xprv at to produce the slot pubkey matching the
    // redeem-script.
    let multisig_derivation_index = account.clone().as_derivation_capable()?.cosigner_index();

    // PSKTGenerator requires a PSKBSigner by construction but does not invoke
    // it during stream polling; the placeholder uses the first cosigner's
    // keydata.
    let placeholder_keydata = prv_key_data_store
        .load_key_data(&wallet_secret, &prv_key_data_ids[0])
        .await?
        .ok_or(Error::PrivateKeyNotFound(prv_key_data_ids[0]))?;
    let placeholder_signer = Arc::new(PSKBSigner::new(account.clone(), placeholder_keydata, payment_secret.clone()));

    let generator = Generator::try_new(settings, None, Some(abortable))?;
    let pskt_generator = PSKTGenerator::new(generator.clone(), placeholder_signer, account.wallet().address_prefix()?);
    let mut accumulator = bundle_from_pskt_generator(pskt_generator).await?;

    // Populate `redeem_script` on every PSKT input via the shared helper.
    // The PSKT-conversion path (`wallet/pskt/src/convert.rs::Inner::try_from`)
    // builds inputs without populating this field; without it the Finalizer's
    // `None` branch emits an empty `script_sig` and consensus rejects the
    // extracted transaction with a P2SH-hash mismatch.
    populate_multisig_redeem_scripts(account.clone(), &mut accumulator, k).await?;

    for prv_key_data_id in prv_key_data_ids.iter() {
        let already_fully_signed =
            accumulator.iter().all(|pskt_inner| pskt_inner.inputs.iter().all(|input| input.partial_sigs.len() >= k as usize));
        if already_fully_signed {
            break;
        }

        let prv_key_data = prv_key_data_store
            .load_key_data(&wallet_secret, prv_key_data_id)
            .await?
            .ok_or(Error::PrivateKeyNotFound(*prv_key_data_id))?;

        let this_xpub = prv_key_data.create_xpub(payment_secret.as_ref(), MULTISIG_ACCOUNT_KIND.into(), 0).await?;
        let this_xpub_string = this_xpub.to_string(Some(KeyPrefix::XPUB));

        // Validate the cosigner's seed is part of the multisig set. Use a linear scan: the
        // re-emitted `xpub_keys_strings` vector preserves the persisted vector's order,
        // which is not guaranteed to be sorted under the xpub-prefix form (a wallet
        // persisted under a code path that did not normalize xpub prefixes stores the
        // vector in a mixed-prefix sort order whose entries reorder when re-encoded as `xpub`).
        if !xpub_keys_strings.iter().any(|s| s == &this_xpub_string) {
            return Err(Error::MultisigCosignerXpubNotFound { prv_key_data_id: *prv_key_data_id, derived_xpub: this_xpub_string });
        }

        let per_cosigner_bundle = pskb_signer_for_multisig_cosigner(
            &accumulator,
            account.clone(),
            &prv_key_data,
            payment_secret.as_ref(),
            multisig_derivation_index,
            network_id,
        )
        .await?;

        if accumulator.0.len() != per_cosigner_bundle.0.len() {
            return Err(Error::custom("multisig signed bundle PSKT count mismatch with accumulator"));
        }
        for (pskt_idx, signed_pskt_inner) in per_cosigner_bundle.0.into_iter().enumerate() {
            if accumulator.0[pskt_idx].inputs.len() != signed_pskt_inner.inputs.len() {
                return Err(Error::custom("multisig signed bundle PSKT input count mismatch with accumulator"));
            }
            for (input_idx, signed_input) in signed_pskt_inner.inputs.into_iter().enumerate() {
                let accum_input = std::mem::take(&mut accumulator.0[pskt_idx].inputs[input_idx]);
                accumulator.0[pskt_idx].inputs[input_idx] = (accum_input + signed_input).map_err(|e| Error::custom(e.to_string()))?;
            }
        }
    }

    Ok((accumulator, generator.summary()))
}

/// Populate `input.redeem_script` and `input.bip32_derivations` on every
/// PSKT input of every PSKT in the bundle.
///
/// **Redeem script.** The PSKT-conversion path
/// (`wallet/pskt/src/convert.rs::Inner::try_from`) builds inputs with
/// `redeem_script: None`; the Finalizer's `Some(redeem_script)` branch is
/// what assembles a P2SH-multisig `script_sig` of the shape
/// `OpData65 || sig_1 || sighash_type || ... || OpData65 || sig_K || sighash_type || PUSHDATA(redeem_script)`.
/// Without `redeem_script` the Finalizer's `None` branch emits signatures
/// with no trailing redeem-script push, the assembled `script_sig` fails
/// the consensus-side P2SH script-hash check at extract, and the transaction
/// is rejected with `EvalFalse`.
///
/// The redeem-script per input is `multisig_redeem_script(slot_pubkeys, k)`
/// where each slot pubkey is derived from the corresponding cosigner xpub at
/// `derive_child(funded_cosigner_index).derive_child(address_type).derive_child(address_index)`.
/// **The funded cosigner_index is the address's own family**, not the local
/// wallet's; recovered from the family-aware `address_family_index` lookup
/// over every cosigner-prefix family the wallet watches. Every xpub in the
/// emitted script is derived through the same `path` argument, and the path
/// is the funded UTXO's address path. Each cosigner-prefix family thus has
/// a distinct P2SH script-hash; spending a UTXO in family Y produces a
/// redeem-script keyed to Y's derivation chain.
///
/// **bip32 derivations.** The helper additionally records the funded address's
/// derivation path (`m/45'/111111'/account_index'/<funded_cosigner_index>/<address_type>/<address_index>`)
/// on the PSKT input via `bip32_derivations`, keyed by the local cosigner's
/// slot pubkey at that path. At sign time, every cosigner reads the recorded
/// path, derives their own xprv at the same path, produces the cosigner's
/// slot pubkey, and signs the matching redeem-script slot. The recorded
/// path attribution makes K-of-N spending of any cosigner-prefix family
/// possible without requiring each cosigner to re-derive the family from
/// the UTXO address locally.
///
/// The shared helper is reused by both the operator-Send path
/// (`build_multisig_signed_bundle`) and the REPL `pskb sign` path
/// (`MultiSig::pskb_sign`); idempotency on pre-populated inputs makes the
/// call safe in multi-party PSKT exchange chains where an upstream cosigner
/// has already attached the redeem-script and derivation attribution.
pub(crate) async fn populate_multisig_redeem_scripts(account: Arc<dyn Account>, bundle: &mut Bundle, k: u16) -> Result<()> {
    let derivation_capable = account.clone().as_derivation_capable()?;
    let derivation = derivation_capable.derivation();
    let local_cosigner_index = derivation_capable.cosigner_index();
    let account_index = derivation_capable.account_index();
    let xpub_keys = account.xpub_keys().ok_or(Error::custom("multisig account missing xpub_keys"))?.clone();
    let network_id = account.wallet().clone().network_id()?;
    let local_xpub = xpub_keys
        .get(local_cosigner_index as usize)
        .ok_or_else(|| Error::custom("multisig account local cosigner_index out of xpub range"))?
        .clone();
    let local_key_fingerprint = local_xpub.fingerprint();

    for pskt_inner in bundle.0.iter_mut() {
        for input in pskt_inner.inputs.iter_mut() {
            let needs_redeem_script = input.redeem_script.is_none();
            let needs_bip32_derivations = input.bip32_derivations.is_empty();
            if !needs_redeem_script && !needs_bip32_derivations {
                continue;
            }

            let utxo_entry = input.utxo_entry.as_ref().ok_or_else(|| Error::custom("input missing utxo_entry"))?;
            let address = extract_script_pub_key_address(&utxo_entry.script_public_key, network_id.into())?;
            let (funded_cosigner_index, address_type, address_index) = derivation.address_family_index(&address)?;

            if needs_redeem_script {
                let mut slot_pubkeys: Vec<secp256k1::PublicKey> = Vec::with_capacity(xpub_keys.len());
                for xpub in xpub_keys.iter() {
                    let derived = xpub
                        .clone()
                        .derive_child(ChildNumber::new(funded_cosigner_index, false)?)?
                        .derive_child(ChildNumber::new(address_type.index(), false)?)?
                        .derive_child(ChildNumber::new(address_index, false)?)?;
                    slot_pubkeys.push(*derived.public_key());
                }
                let redeem_script =
                    multisig_redeem_script(slot_pubkeys.iter().map(|pk| pk.x_only_public_key().0.serialize()), k as usize)?;
                input.redeem_script = Some(redeem_script);
            }

            if needs_bip32_derivations {
                let local_derived = local_xpub
                    .clone()
                    .derive_child(ChildNumber::new(funded_cosigner_index, false)?)?
                    .derive_child(ChildNumber::new(address_type.index(), false)?)?
                    .derive_child(ChildNumber::new(address_index, false)?)?;
                let local_slot_pubkey = *local_derived.public_key();
                let derivation_path: DerivationPath =
                    format!("m/45'/111111'/{account_index}'/{funded_cosigner_index}/{}/{address_index}", address_type.index())
                        .parse()
                        .map_err(|e: kaspa_bip32::Error| Error::custom(format!("multisig derivation path parse failed: {e}")))?;
                input
                    .bip32_derivations
                    .insert(local_slot_pubkey, Some(KeySource { key_fingerprint: local_key_fingerprint, derivation_path }));
            }
        }
    }
    Ok(())
}

impl DerivationCapableAccount for MultiSig {
    fn derivation(&self) -> Arc<dyn AddressDerivationManagerTrait> {
        self.derivation.clone()
    }

    /// Drop the account_index() = 0 hardcode and let each multisig account
    /// carry its own hardened account_index. This makes multi-account-multisig
    /// cryptographically meaningful rather than just storage-segregation, and
    /// preserves legacy byte-identity for the common single-multisig-account
    /// case (account_index = 0).
    fn account_index(&self) -> u64 {
        self.account_index
    }

    /// Override the trait-default `cosigner_index() -> 0` with the value persisted on the
    /// multisig account at create-time. The same value is fed to `AddressDerivationManager`
    /// as the shared BIP-32 derivation step applied to every cosigner's xpub when assembling
    /// the redeem-script's pubkey list. Sign-time per-cosigner key derivation MUST use the
    /// same value or the signing key's pubkey will not match the redeem-script slot it
    /// occupies, producing an `EvalFalse` consensus rejection at PSKT extract.
    fn cosigner_index(&self) -> u32 {
        self.cosigner_index.map(|v| v as u32).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;

    #[test]
    fn test_storage_multisig() -> Result<()> {
        let storable_in = Payload::new(vec![make_xpub()].into(), Some(42), 0xc0fe, false, 0);
        let guard = StorageGuard::new(&storable_in);
        let storable_out = guard.validate()?;

        assert_eq!(storable_in.cosigner_index, storable_out.cosigner_index);
        assert_eq!(storable_in.minimum_signatures, storable_out.minimum_signatures);
        assert_eq!(storable_in.ecdsa, storable_out.ecdsa);
        assert_eq!(storable_in.account_index, storable_out.account_index);
        assert_eq!(storable_in.xpub_keys.len(), storable_out.xpub_keys.len());
        for idx in 0..storable_in.xpub_keys.len() {
            assert_eq!(storable_in.xpub_keys[idx], storable_out.xpub_keys[idx]);
        }

        Ok(())
    }
}
