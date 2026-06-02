//!
//! MultiSig account implementation.
//!

use crate::account::Inner;
use crate::account::pskb::{PSKBSigner, PSKTGenerator, bundle_from_pskt_generator, pskb_signer_for_multisig_cosigner};
use crate::account::{Fees, GenerationNotifier, PaymentDestination};
use crate::derivation::{AddressDerivationManager, AddressDerivationManagerTrait};
use crate::imports::*;
use crate::tx::{Generator, GeneratorSettings, GeneratorSummary, PaymentOutput, Signer};
use kaspa_bip32::{ChildNumber, DerivationPath, Prefix as KeyPrefix};
use kaspa_txscript::{extract_script_pub_key_address, multisig_redeem_script, multisig_redeem_script_ecdsa};
use kaspa_wallet_pskt::bundle::Bundle;
use kaspa_wallet_pskt::prelude::KeySource;

pub const MULTISIG_ACCOUNT_KIND: &str = "kaspa-multisig-standard";

pub(crate) fn xpub_seat_index(xpub: &ExtendedPublicKeySecp256k1) -> u64 {
    xpub.attrs().child_number.index() as u64
}

fn xpub_seat_for_derivation(xpub_keys: &ExtendedPublicKeys, cosigner_index: Option<u8>) -> u64 {
    let index = cosigner_index.map(|index| index as usize).unwrap_or(0);
    xpub_keys.get(index).or_else(|| xpub_keys.first()).map(xpub_seat_index).unwrap_or(0)
}

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
    // The local cosigner seats. A registered multisig account is either
    // watch-only (`None`: no local key among the cosigners) or holds one or
    // more local cosigner keys. The vector form matches the on-disk
    // `AccountStorage.prv_key_data_ids` wrapper and the account-id hash
    // input; K-of-N signing paths consume every stored local seat until the
    // threshold is reached.
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
            xpub_seat_for_derivation(&xpub_keys, cosigner_index),
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
            xpub_seat_for_derivation(&xpub_keys, cosigner_index),
            cosigner_index.map(|v| v as u32),
            minimum_signatures,
            address_derivation_indexes,
        )
        .await?;

        let prv_key_data_ids: Option<Arc<Vec<PrvKeyDataId>>> = storage.prv_key_data_ids.clone().try_into()?;

        Ok(Self { inner, xpub_keys, cosigner_index, minimum_signatures, ecdsa, account_index, derivation, prv_key_data_ids })
    }

    pub fn prv_key_data_ids(&self) -> &Option<Arc<Vec<PrvKeyDataId>>> {
        &self.prv_key_data_ids
    }

    pub fn minimum_signatures(&self) -> u16 {
        self.minimum_signatures
    }

    pub fn seat_indexes(&self) -> Vec<u64> {
        self.xpub_keys.iter().map(xpub_seat_index).collect()
    }

    fn watch_only(&self) -> bool {
        self.prv_key_data_ids.is_none()
    }

    /// Count the cosigner positions the stored local keys can sign. Every
    /// stored own xpub backed by a local key is one seat; one key backs
    /// several seats when several of its hardened children are registered
    /// in the same group. Watch-only accounts count zero.
    async fn matched_local_seat_count(self: &Arc<Self>, wallet_secret: &Secret, payment_secret: Option<&Secret>) -> Result<usize> {
        if self.prv_key_data_ids.is_none() {
            return Ok(0);
        }
        let mut seats = 0;
        for prv_key_data in self.load_local_cosigner_keydata(wallet_secret).await? {
            seats += multisig_cosigner_indexes(self.clone().as_dyn_arc(), &prv_key_data, payment_secret).await?.len();
        }
        Ok(seats)
    }

    async fn load_local_cosigner_keydata(&self, wallet_secret: &Secret) -> Result<Vec<PrvKeyData>> {
        let prv_key_data_ids = self.prv_key_data_ids.as_ref().ok_or(Error::AccountKindFeature)?;
        let prv_key_data_store = self.wallet().store().as_prv_key_data_store()?;
        let mut keydata = Vec::with_capacity(prv_key_data_ids.len());
        for prv_key_data_id in prv_key_data_ids.iter() {
            keydata.push(
                prv_key_data_store
                    .load_key_data(wallet_secret, prv_key_data_id)
                    .await?
                    .ok_or(Error::PrivateKeyNotFound(*prv_key_data_id))?,
            );
        }
        Ok(keydata)
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

    /// Load the local cosigner's key data for the P2PK send routing branch.
    /// Precondition: `route_as_single_sig` returned `true`, which guarantees
    /// this account holds exactly one local seat.
    async fn load_sole_cosigner_keydata(&self, wallet_secret: &Secret) -> Result<PrvKeyData> {
        self.prv_key_data(wallet_secret.clone()).await
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

    fn ecdsa(&self) -> bool {
        self.ecdsa
    }

    fn prv_key_data_id(&self) -> Result<&PrvKeyDataId> {
        // Trait-default single-key paths only support one local key. The
        // multisig K-of-N paths use `prv_key_data_ids` directly so multi-seat
        // accounts can consume every local cosigner.
        self.prv_key_data_ids.as_ref().and_then(|ids| ids.first()).ok_or(Error::AccountKindFeature)
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
        .with_property(AccountDescriptorProperty::AccountIndex, self.account_index.into())
        .with_property(AccountDescriptorProperty::Other("Seat Indexes".to_string()), format!("{:?}", self.seat_indexes()).into())
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
        let index_suffix = format!("[slot={} seats={:?}]", self.account_index, self.seat_indexes());
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
        // Broadcast path: a partial bundle is rejected at consensus
        // `OpCheckMultiSig` extract. Reject only when the cosigner positions
        // the stored local keys can sign cannot reach the K quorum;
        // otherwise the bundle builder signs per matched position until the
        // threshold is reached.
        let local_seats = self.matched_local_seat_count(&wallet_secret, payment_secret.as_ref()).await?;
        if local_seats < self.minimum_signatures as usize {
            return Err(Error::MultisigInsufficientCosignerMaterial { local: local_seats, required: self.minimum_signatures });
        }
        let settings =
            GeneratorSettings::try_new_with_account(self.clone().as_dyn_arc(), destination, fee_rate, priority_fee_sompi, payload)?;

        let (bundle, summary) = build_multisig_signed_bundle(
            self.clone().as_dyn_arc(),
            xpub_keys_strings,
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
        // Broadcast path: same quorum reject as `send`.
        let local_seats = self.matched_local_seat_count(&wallet_secret, payment_secret.as_ref()).await?;
        if local_seats < self.minimum_signatures as usize {
            return Err(Error::MultisigInsufficientCosignerMaterial { local: local_seats, required: self.minimum_signatures });
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
        // A watch-only account holds no local seat and cannot produce even a
        // partial signature. A local-seat account contributes every stored
        // local cosigner signature up to the threshold; the returned bundle is
        // partial when local material is insufficient and completes through
        // downstream `pskb_sign` rounds.
        if self.watch_only() {
            return Err(Error::MultisigInsufficientCosignerMaterial { local: 0, required: self.minimum_signatures });
        }
        let settings =
            GeneratorSettings::try_new_with_account(self.clone().as_dyn_arc(), destination, fee_rate, priority_fee_sompi, payload)?;

        let (bundle, _summary) = build_multisig_signed_bundle(
            self.clone().as_dyn_arc(),
            xpub_keys_strings,
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
    ///    `m/45'/111111'/<seat>'/<cosigner_index>/<address_type>/<address_index>`
    ///    (the hardened seat read from the signing key's own xpub),
    ///    not the BIP-32 single-sig path. Routing through
    ///    `pskb_signer_for_multisig_cosigner` enforces this; the
    ///    trait-default path routes through `pskb_signer_for_address` whose
    ///    derivation is single-sig and produces signing keys whose pubkeys
    ///    do not match any redeem-script slot.
    ///
    /// This round loads the operator's own cosigner key data, signs every
    /// PSKT input whose redeem-script slot those keys can satisfy, and merges
    /// the resulting partial signatures into the accumulator until K is
    /// reached. K-of-N completion across independent cosigner
    /// wallets proceeds by exchanging the partial bundle to the next
    /// cosigner's `pskb_sign` round; the per-input `K`-cap gate (here, the
    /// already-fully-signed short-circuit) keeps the bundle at no more than
    /// K signatures so the resulting `script_sig` does not trip `CleanStack`
    /// at consensus.
    async fn pskb_sign(
        self: Arc<Self>,
        bundle: &Bundle,
        wallet_secret: Secret,
        payment_secret: Option<Secret>,
        _sign_for_address: Option<&Address>,
    ) -> Result<Bundle, Error> {
        if self.watch_only() {
            return Err(Error::MultisigInsufficientCosignerMaterial { local: 0, required: self.minimum_signatures });
        }

        let k = self.minimum_signatures;
        let network_id = self.wallet().clone().network_id()?;

        let account_dyn = self.clone().as_dyn_arc();
        let mut accumulator = Bundle(bundle.0.clone());
        populate_multisig_redeem_scripts(account_dyn.clone(), &mut accumulator, k).await?;

        if !bundle_reaches_threshold(&accumulator, k) {
            for prv_key_data in self.load_local_cosigner_keydata(&wallet_secret).await? {
                if bundle_reaches_threshold(&accumulator, k) {
                    break;
                }
                for cosigner_index in multisig_cosigner_indexes(account_dyn.clone(), &prv_key_data, payment_secret.as_ref()).await? {
                    if bundle_reaches_threshold(&accumulator, k) {
                        break;
                    }
                    let per_cosigner_bundle = pskb_signer_for_multisig_cosigner(
                        &accumulator,
                        account_dyn.clone(),
                        &prv_key_data,
                        payment_secret.as_ref(),
                        cosigner_index,
                        network_id,
                    )
                    .await?;
                    merge_cosigner_bundle(&mut accumulator, per_cosigner_bundle)?;
                }
            }
        }

        Ok(accumulator)
    }

    /// Transfer funds from this multisig account to another wallet account.
    ///
    /// Mirrors `MultiSig::send`'s routing: the `route_as_single_sig` P2PK seat
    /// takes the single-signature `Signer` path; every other shape assembles
    /// the K-of-N bundle via `build_multisig_signed_bundle` and broadcasts it.
    /// The destination account's receive address and utxo context are resolved
    /// exactly as the trait-default `transfer` does. A `K >= 2` group whose
    /// local seat cannot reach the quorum surfaces
    /// `MultisigInsufficientCosignerMaterial`, identical to `send` / `sweep`,
    /// because a partial bundle is rejected at the consensus `OpCheckMultiSig`
    /// extract.
    async fn transfer(
        self: Arc<Self>,
        destination_account_id: AccountId,
        transfer_amount_sompi: u64,
        fee_rate: Option<f64>,
        priority_fee_sompi: Fees,
        wallet_secret: Secret,
        payment_secret: Option<Secret>,
        abortable: &Abortable,
        notifier: Option<GenerationNotifier>,
        guard: &WalletGuard,
    ) -> Result<(GeneratorSummary, Vec<kaspa_hashes::Hash>)> {
        let destination_account = self
            .wallet()
            .get_account_by_id(&destination_account_id, guard)
            .await?
            .ok_or(Error::AccountNotFound(destination_account_id))?;
        let destination_address = destination_account.receive_address()?;
        let destination = PaymentDestination::from(PaymentOutput::new(destination_address, transfer_amount_sompi));

        let settings =
            GeneratorSettings::try_new_with_account(self.clone().as_dyn_arc(), destination, fee_rate, priority_fee_sompi, None)?
                .utxo_context_transfer(destination_account.utxo_context());

        if self.route_as_single_sig() {
            let keydata = self.load_sole_cosigner_keydata(&wallet_secret).await?;
            let signer = Arc::new(Signer::new(self.clone().as_dyn_arc(), keydata, payment_secret));
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

        let local_seats = self.matched_local_seat_count(&wallet_secret, payment_secret.as_ref()).await?;
        if local_seats < self.minimum_signatures as usize {
            return Err(Error::MultisigInsufficientCosignerMaterial { local: local_seats, required: self.minimum_signatures });
        }

        let xpub_keys_strings: Vec<String> = self.xpub_keys.iter().map(|k| k.to_string(Some(KeyPrefix::XPUB))).collect();
        let (bundle, summary) = build_multisig_signed_bundle(
            self.clone().as_dyn_arc(),
            xpub_keys_strings,
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
}

/// Merge a per-cosigner signed bundle into the accumulator, adding each
/// input's partial signatures via `Input::add` (previous-outpoint
/// validated). The two bundles MUST carry identical PSKT and per-PSKT input
/// counts; a mismatch is a signer-chain programming error, not a runtime
/// condition.
fn merge_cosigner_bundle(accumulator: &mut Bundle, per_cosigner_bundle: Bundle) -> Result<()> {
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
    Ok(())
}

fn bundle_reaches_threshold(bundle: &Bundle, k: u16) -> bool {
    bundle.iter().all(|pskt_inner| pskt_inner.inputs.iter().all(|input| input.partial_sigs.len() >= k as usize))
}

async fn load_account_local_cosigner_keydata(account: Arc<dyn Account>, wallet_secret: &Secret) -> Result<Vec<PrvKeyData>> {
    let prv_key_data_ids: Vec<PrvKeyDataId> = (&account.to_storage()?.prv_key_data_ids).into_iter().collect();
    if prv_key_data_ids.is_empty() {
        return Err(Error::AccountKindFeature);
    }

    let prv_key_data_store = account.wallet().store().as_prv_key_data_store()?;
    let mut keydata = Vec::with_capacity(prv_key_data_ids.len());
    for prv_key_data_id in prv_key_data_ids {
        keydata.push(
            prv_key_data_store
                .load_key_data(wallet_secret, &prv_key_data_id)
                .await?
                .ok_or(Error::PrivateKeyNotFound(prv_key_data_id))?,
        );
    }
    Ok(keydata)
}

/// Resolve every cosigner position the given key backs: for each stored
/// xpub, derive the key's xpub at that xpub's embedded seat and collect the
/// positions whose full serialization matches. One key backs several
/// positions when several of its hardened children are registered in the
/// same group.
async fn multisig_cosigner_indexes(
    account: Arc<dyn Account>,
    prv_key_data: &PrvKeyData,
    payment_secret: Option<&Secret>,
) -> Result<Vec<u32>> {
    let xpub_keys = account.xpub_keys().ok_or(Error::custom("multisig account missing xpub_keys"))?;
    let mut matched = Vec::new();
    let mut last_derived_xpub = String::new();
    for (index, xpub) in xpub_keys.iter().enumerate() {
        let seat_index = xpub_seat_index(xpub);
        let derived_xpub = prv_key_data.create_xpub(payment_secret, MULTISIG_ACCOUNT_KIND.into(), seat_index).await?;
        let derived_xpub_string = derived_xpub.to_string(Some(KeyPrefix::XPUB));
        if derived_xpub_string == xpub.to_string(Some(KeyPrefix::XPUB)) {
            matched.push(index as u32);
        } else {
            last_derived_xpub = derived_xpub_string;
        }
    }
    if matched.is_empty() {
        return Err(Error::MultisigCosignerXpubNotFound { prv_key_data_id: prv_key_data.id, derived_xpub: last_derived_xpub });
    }
    Ok(matched)
}

/// Build a PSKB carrying the local wallet's cosigner signatures.
///
/// Algorithm: build the empty PSKT bundle once via the standard PSKBSigner
/// machinery (the placeholder signer is held but never invoked during stream
/// polling), populate every input's redeem-script, then apply local cosigner
/// signatures until the threshold is reached or local material is exhausted.
///
/// A bundle whose local seat count reaches K is complete and ready for
/// broadcast. A bundle with fewer local signatures remains partial and
/// completes through downstream `pskb_sign` exchange rounds across other
/// cosigner wallets before broadcast. Callers that directly broadcast the
/// returned bundle (e.g., `MultiSig::send` / `MultiSig::sweep`) MUST reject
/// the partial case themselves before invoking this helper, since a partial
/// bundle is rejected at the consensus `OpCheckMultiSig` extract.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn build_multisig_signed_bundle(
    account: Arc<dyn Account>,
    xpub_keys_strings: Vec<String>,
    minimum_signatures: u16,
    settings: GeneratorSettings,
    wallet_secret: Secret,
    payment_secret: Option<Secret>,
    abortable: &Abortable,
    _notifier: Option<GenerationNotifier>,
) -> Result<(Bundle, GeneratorSummary)> {
    let k = minimum_signatures;

    let network_id = account.wallet().clone().network_id()?;
    let local_keydata = load_account_local_cosigner_keydata(account.clone(), &wallet_secret).await?;

    // PSKTGenerator requires a PSKBSigner by construction but does not invoke
    // it during stream polling; the placeholder uses the local cosigner keydata.
    let placeholder_signer = Arc::new(PSKBSigner::new(account.clone(), local_keydata[0].clone(), payment_secret.clone()));

    let generator = Generator::try_new(settings, None, Some(abortable))?;
    let pskt_generator = PSKTGenerator::new(generator.clone(), placeholder_signer, account.wallet().address_prefix()?);
    let mut accumulator = bundle_from_pskt_generator(pskt_generator).await?;

    // Populate `redeem_script` on every PSKT input via the shared helper.
    // The PSKT-conversion path (`wallet/pskt/src/convert.rs::Inner::try_from`)
    // builds inputs without populating this field; without it the Finalizer's
    // `None` branch emits an empty `script_sig` and consensus rejects the
    // extracted transaction with a P2SH-hash mismatch.
    populate_multisig_redeem_scripts(account.clone(), &mut accumulator, k).await?;

    for prv_key_data in local_keydata.iter() {
        if bundle_reaches_threshold(&accumulator, k) {
            break;
        }

        for cosigner_index in multisig_cosigner_indexes(account.clone(), prv_key_data, payment_secret.as_ref()).await? {
            if bundle_reaches_threshold(&accumulator, k) {
                break;
            }
            let local_xpub_string = account
                .xpub_keys()
                .and_then(|xpubs| xpubs.get(cosigner_index as usize))
                .map(|xpub| xpub.to_string(Some(KeyPrefix::XPUB)))
                .ok_or_else(|| Error::custom("multisig account local cosigner_index out of xpub range"))?;
            if !xpub_keys_strings.iter().any(|s| s == &local_xpub_string) {
                return Err(Error::MultisigCosignerXpubNotFound { prv_key_data_id: prv_key_data.id, derived_xpub: local_xpub_string });
            }
            let per_cosigner_bundle = pskb_signer_for_multisig_cosigner(
                &accumulator,
                account.clone(),
                prv_key_data,
                payment_secret.as_ref(),
                cosigner_index,
                network_id,
            )
            .await?;
            merge_cosigner_bundle(&mut accumulator, per_cosigner_bundle)?;
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
/// derivation path (`m/45'/111111'/<seat>'/<funded_cosigner_index>/<address_type>/<address_index>`,
/// one entry per cosigner xpub, each at the hardened seat embedded in that xpub)
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
    let xpub_keys = account.xpub_keys().ok_or(Error::custom("multisig account missing xpub_keys"))?.clone();
    let network_id = account.wallet().clone().network_id()?;

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
                // The spending redeem script MUST byte-match the one the
                // address was derived from, or the P2SH script-hash check
                // fails at extract. ECDSA accounts encode 33-byte compressed
                // pubkeys + OpCheckMultiSigECDSA; Schnorr accounts encode
                // 32-byte x-only pubkeys + OpCheckMultiSig. This mirrors the
                // address-derivation branch in `derivation::create_multisig_address`.
                let redeem_script = if account.ecdsa() {
                    multisig_redeem_script_ecdsa(slot_pubkeys.iter().map(|pk| pk.serialize()), k as usize)?
                } else {
                    multisig_redeem_script(slot_pubkeys.iter().map(|pk| pk.x_only_public_key().0.serialize()), k as usize)?
                };
                input.redeem_script = Some(redeem_script);
            }

            if needs_bip32_derivations {
                for xpub in xpub_keys.iter() {
                    let seat_index = xpub_seat_index(xpub);
                    let derived = xpub
                        .clone()
                        .derive_child(ChildNumber::new(funded_cosigner_index, false)?)?
                        .derive_child(ChildNumber::new(address_type.index(), false)?)?
                        .derive_child(ChildNumber::new(address_index, false)?)?;
                    let slot_pubkey = *derived.public_key();
                    let derivation_path: DerivationPath =
                        format!("m/45'/111111'/{seat_index}'/{funded_cosigner_index}/{}/{address_index}", address_type.index())
                            .parse()
                            .map_err(|e: kaspa_bip32::Error| Error::custom(format!("multisig derivation path parse failed: {e}")))?;
                    input
                        .bip32_derivations
                        .insert(slot_pubkey, Some(KeySource { key_fingerprint: xpub.fingerprint(), derivation_path }));
                }
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

    fn create_private_keys<'l>(
        &self,
        key_data: &PrvKeyData,
        payment_secret: &Option<Secret>,
        receive: &[(&'l Address, u32)],
        change: &[(&'l Address, u32)],
    ) -> Result<Vec<(&'l Address, secp256k1::SecretKey)>> {
        let payload = key_data.payload.decrypt(payment_secret.as_ref())?;
        let xkey = payload.get_xprv(payment_secret.as_ref())?;
        let cosigner_index = self.cosigner_index();
        let seat_index = xpub_seat_for_derivation(&self.xpub_keys, self.cosigner_index);
        crate::account::create_private_keys(&self.account_kind(), cosigner_index, seat_index, &xkey, receive, change)
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
