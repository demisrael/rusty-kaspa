//! Errors raised by the wire codec.

use thiserror::Error;

#[derive(Debug, Error)]
pub enum SerializationError {
    #[error("proto decode error: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("proto encode error: {0}")]
    Encode(#[from] prost::EncodeError),
    #[error("invalid wire {field}: {reason}")]
    Invalid { field: &'static str, reason: String },
    #[error("missing required wire field {0}")]
    Missing(&'static str),
}
