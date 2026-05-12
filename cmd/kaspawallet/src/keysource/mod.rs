//! Key-source abstraction. The wallet binary is designed to host
//! multiple key backends (keyfile-backed in this build; sibling
//! cycles add KDX / Tangem / Ledger / kaspa-ng). Backends plug in
//! by implementing `KeySource` (always) and `DerivableKeySource`
//! (when the backend exposes a BIP-32 derivation chain). The
//! split keeps a fixed-address backend (Tangem) able to
//! implement `KeySource` without faking a chain.

mod default_path;
mod error;
mod legacy_go;
mod resolver;
mod traits;

#[cfg(test)]
mod tests;

pub use default_path::{default_keys_file, require_existing_keyfile, resolve_keys_file_path};
pub use error::{KeySourceError, ResolveError};
pub use legacy_go::LegacyGoKeyfile;
pub use resolver::{KeyChain, resolve_backend};
pub use traits::{DerivableKeySource, KeySource};
