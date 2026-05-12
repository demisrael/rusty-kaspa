//! Subcommand-style wallet binary: keyfile codec, multisig signing,
//! transaction construction, and a gRPC daemon mode.

pub mod cli;
pub mod coinsel;
pub mod daemon;
pub mod dispatch;
pub mod keyfile;
pub mod keysource;
pub mod mass;
pub mod parse;
pub mod serialization;
pub mod sign;
pub mod transaction;
pub mod transactions_hex;
pub mod version;
