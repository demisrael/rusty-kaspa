//!
//! Storage wrapper for account data.
//!

use crate::imports::*;

const ACCOUNT_SETTINGS_VERSION: u32 = 0;

#[derive(Default, Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub struct AccountSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub meta: Option<Vec<u8>>,
}

impl BorshSerialize for AccountSettings {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        BorshSerialize::serialize(&ACCOUNT_SETTINGS_VERSION, writer)?;
        BorshSerialize::serialize(&self.name, writer)?;
        BorshSerialize::serialize(&self.meta, writer)?;

        Ok(())
    }
}

impl BorshDeserialize for AccountSettings {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> IoResult<Self> {
        let _version: u32 = BorshDeserialize::deserialize_reader(reader)?;
        let name = BorshDeserialize::deserialize_reader(reader)?;
        let meta = BorshDeserialize::deserialize_reader(reader)?;

        Ok(Self { name, meta })
    }
}

/// A [`Storable`] variant used explicitly for [`Account`] payload storage.
pub trait AccountStorable: Storable {}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccountStorage {
    pub kind: AccountKind,
    pub id: AccountId,
    pub storage_key: AccountStorageKey,
    pub prv_key_data_ids: AssocPrvKeyDataIds,
    pub settings: AccountSettings,
    pub serialized: Vec<u8>,
}

impl AccountStorage {
    const STORAGE_MAGIC: u32 = 0x4153414b;
    const STORAGE_VERSION: u32 = 0;

    pub fn try_new<A>(
        kind: AccountKind,
        id: &AccountId,
        storage_key: &AccountStorageKey,
        prv_key_data_ids: AssocPrvKeyDataIds,
        settings: AccountSettings,
        serialized: A,
    ) -> Result<Self>
    where
        A: AccountStorable,
    {
        Ok(Self { id: *id, storage_key: *storage_key, kind, prv_key_data_ids, settings, serialized: borsh::to_vec(&serialized)? })
    }

    pub fn id(&self) -> &AccountId {
        &self.id
    }

    pub fn storage_key(&self) -> &AccountStorageKey {
        &self.storage_key
    }

    pub fn serialized(&self) -> &[u8] {
        &self.serialized
    }
}

impl std::fmt::Debug for AccountStorage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AccountStorage")
            .field("kind", &self.kind)
            .field("id", &self.id)
            .field("storage_key", &self.storage_key)
            .field("prv_key_data_ids", &self.prv_key_data_ids)
            .field("settings", &self.settings)
            .field("serialized", &self.serialized.to_hex())
            .finish()
    }
}

impl BorshSerialize for AccountStorage {
    fn serialize<W: std::io::Write>(&self, writer: &mut W) -> std::io::Result<()> {
        StorageHeader::new(Self::STORAGE_MAGIC, Self::STORAGE_VERSION).serialize(writer)?;
        BorshSerialize::serialize(&self.kind, writer)?;
        BorshSerialize::serialize(&self.id, writer)?;
        BorshSerialize::serialize(&self.storage_key, writer)?;
        BorshSerialize::serialize(&self.prv_key_data_ids, writer)?;
        BorshSerialize::serialize(&self.settings, writer)?;
        BorshSerialize::serialize(&self.serialized, writer)?;

        Ok(())
    }
}

impl BorshDeserialize for AccountStorage {
    fn deserialize_reader<R: std::io::Read>(reader: &mut R) -> IoResult<Self> {
        let StorageHeader { version: _, .. } =
            StorageHeader::deserialize_reader(reader)?.try_magic(Self::STORAGE_MAGIC)?.try_version(Self::STORAGE_VERSION)?;

        let kind = BorshDeserialize::deserialize_reader(reader)?;
        let id = BorshDeserialize::deserialize_reader(reader)?;
        let storage_key = BorshDeserialize::deserialize_reader(reader)?;
        let prv_key_data_ids = BorshDeserialize::deserialize_reader(reader)?;
        let settings = BorshDeserialize::deserialize_reader(reader)?;
        let serialized = BorshDeserialize::deserialize_reader(reader)?;

        Ok(Self { kind, id, storage_key, prv_key_data_ids, settings, serialized })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::*;

    #[test]
    fn test_storage_account_storage_wrapper() -> Result<()> {
        let (id, storage_key) = make_account_hashes(from_data(&BIP32_ACCOUNT_KIND.into(), &[0x00, 0x01, 0x02, 0x03]));
        let prv_key_data_id = PrvKeyDataId::new(0xcafe);
        let storable = bip32::Payload::new(0, ExtendedPublicKeys::default(), false);
        let storable_in = AccountStorage::try_new(
            BIP32_ACCOUNT_KIND.into(),
            &id,
            &storage_key,
            prv_key_data_id.into(),
            AccountSettings::default(),
            storable,
        )?;
        let guard = StorageGuard::new(&storable_in);
        let storable_out = guard.validate()?;

        assert_eq!(storable_in.kind, storable_out.kind);
        assert_eq!(storable_in.id, storable_out.id);
        assert_eq!(storable_in.storage_key, storable_out.storage_key);
        assert_eq!(storable_in.serialized, storable_out.serialized);

        Ok(())
    }

    /// Positive control for the no-migration invariant: a v0-encoded
    /// `AccountStorage` round-trips byte-identically through the
    /// deserialize -> serialize path. `STORAGE_VERSION` stays at 0 and the
    /// `prv_key_data_ids` field remains populated in both directions. Pins
    /// the on-disk Borsh format UNCHANGED invariant.
    #[test]
    fn account_storage_unchanged_on_disk_format() -> Result<()> {
        use borsh::BorshDeserialize;

        let (id, storage_key) = make_account_hashes(from_data(&BIP32_ACCOUNT_KIND.into(), &[0xa1, 0xa2, 0xa3]));
        let prv_key_data_id = PrvKeyDataId::new(0xface);
        let storable = bip32::Payload::new(7, ExtendedPublicKeys::default(), false);
        let storage_in = AccountStorage::try_new(
            BIP32_ACCOUNT_KIND.into(),
            &id,
            &storage_key,
            prv_key_data_id.into(),
            AccountSettings::default(),
            storable,
        )?;

        let bytes_in = borsh::to_vec(&storage_in)?;
        let storage_out = AccountStorage::try_from_slice(&bytes_in)?;
        let bytes_out = borsh::to_vec(&storage_out)?;

        assert_eq!(bytes_in, bytes_out, "AccountStorage Borsh format must be byte-identical on round-trip (no version bump)");
        assert_eq!(storage_out.kind, storage_in.kind);
        assert_eq!(storage_out.id, storage_in.id);
        assert_eq!(storage_out.storage_key, storage_in.storage_key);
        assert_eq!(storage_out.serialized, storage_in.serialized);

        let header_version = {
            let mut cursor = std::io::Cursor::new(&bytes_in[..]);
            let header = StorageHeader::deserialize_reader(&mut cursor)?;
            header.version
        };
        assert_eq!(header_version, AccountStorage::STORAGE_VERSION);
        assert_eq!(AccountStorage::STORAGE_VERSION, 0, "STORAGE_VERSION stays at 0 (no migration)");

        let id_out: PrvKeyDataId = storage_out.prv_key_data_ids.clone().try_into()?;
        assert_eq!(id_out, prv_key_data_id, "prv_key_data_ids field survives round-trip unchanged");

        Ok(())
    }
}
