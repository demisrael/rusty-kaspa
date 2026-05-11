//! Encode / decode entry points. Mirrors the Go reference's
//! `Serialize*` and `Deserialize*` helpers in
//! `serialization.go`.

use prost::Message;

use super::error::SerializationError;
use super::wire;

/// Encode a `PartiallySignedTransaction` to its protobuf wire
/// form. Equivalent to Go `SerializePartiallySignedTransaction`.
pub fn serialize_partially_signed_transaction(pst: &wire::PartiallySignedTransaction) -> Result<Vec<u8>, SerializationError> {
    Ok(pst.encode_to_vec())
}

/// Decode a protobuf-encoded `PartiallySignedTransaction`.
/// Equivalent to Go `DeserializePartiallySignedTransaction`.
pub fn deserialize_partially_signed_transaction(bytes: &[u8]) -> Result<wire::PartiallySignedTransaction, SerializationError> {
    Ok(wire::PartiallySignedTransaction::decode(bytes)?)
}

/// Encode a `TransactionMessage` (the unsigned-transaction wire
/// shape used by the daemon's `Broadcast` RPC and the legacy
/// `kaspawallet broadcast --transaction <hex>` interop). Mirrors
/// Go `SerializeDomainTransaction`.
pub fn serialize_domain_transaction(tx: &wire::TransactionMessage) -> Result<Vec<u8>, SerializationError> {
    Ok(tx.encode_to_vec())
}

/// Decode a protobuf-encoded `TransactionMessage`. Mirrors Go
/// `DeserializeDomainTransaction`. The Go reference performs an
/// additional `Version <= MaxUint16` check; the wire `version`
/// field is `uint32`, so that runtime check is preserved here.
pub fn deserialize_domain_transaction(bytes: &[u8]) -> Result<wire::TransactionMessage, SerializationError> {
    let tx = wire::TransactionMessage::decode(bytes)?;
    if tx.version > u32::from(u16::MAX) {
        return Err(SerializationError::Invalid { field: "version", reason: format!("version {} exceeds u16::MAX", tx.version) });
    }
    if let Some(subnetwork) = tx.subnetwork_id.as_ref()
        && subnetwork.bytes.len() != 20
    {
        return Err(SerializationError::Invalid {
            field: "subnetworkId.bytes",
            reason: format!("expected 20 bytes, got {}", subnetwork.bytes.len()),
        });
    }
    for (i, input) in tx.inputs.iter().enumerate() {
        if input.sig_op_count > u32::from(u8::MAX) {
            return Err(SerializationError::Invalid {
                field: "inputs.sigOpCount",
                reason: format!("input #{i} sigOpCount {} exceeds u8::MAX", input.sig_op_count),
            });
        }
    }
    Ok(tx)
}
